# `pkg/agent/compliance_watcher.go` — Kubernetes Compliance Watcher

**Package:** `agent`
**Path:** `pkg/agent/compliance_watcher.go`
**Lines:** ~473
**Added:** Mar 22, 2026

---

## Overview

Implements the K8s API-driven compliance event source. Unlike the eBPF monitors, which produce events from live kernel telemetry, this watcher observes Kubernetes object state (pods and network policies) and synthesises compliance events that feed into the same rule engine and downstream pipeline.

This is the mechanism by which CIS controls in the `pod_spec_check` and `network_policy_check` categories are evaluated — they require pod spec fields (seccomp, AppArmor, privilege settings) and namespace-level network policy existence, which are only available from the K8s API, not from kernel events.

---

## Architecture

```
K8s Informer (Pod + NetworkPolicy)
         │
         ├─ Pod Add/Update ──→ onPodEvent()
         │                         │
         │                    shouldProcessPod()   ← only Running pods
         │                         │
         │                    buildPodSpecEvents()  ← one event per container
         │                         │
         │                    handleComplianceEvent()
         │
         └─ NetworkPolicy Add/Update ──→ onNetworkPolicyEvent()
                                              │
                                         buildNetworkPolicyEvent()
                                              │
                                         handleComplianceEvent()
```

All events produced here flow into `agent.handleComplianceEvent()` (defined in `agent.go`), which evaluates them against the same rule engine and buffers them for OWL API / webhook push — identical to eBPF-sourced events.

---

## Functions

### `(a *Agent) startComplianceWatchers(ctx context.Context)`

Entry point, launched as a goroutine from `agent.Start()`. Tracked in `producerWg`.

**Behaviour:**
1. Returns immediately if `K8sClient` is nil (kubernetes_metadata disabled)
2. Builds a `SharedInformerFactory` with `WatchInterval` as the resync period (default 0 = no resync, prevents compliance storms)
3. Registers event handlers on Pod and NetworkPolicy informers
4. Starts factory and waits for cache sync via `cache.WaitForCacheSync()`
5. Closes the `ready` channel to ungate event handler callbacks
6. Blocks on `ctx.Done()` until shutdown

The `ready` channel prevents any compliance events from being emitted before the informer cache is fully populated (avoids spurious or duplicate events during initial sync).

### `(a *Agent) onPodEvent(ctx context.Context, obj interface{}, ready <-chan struct{})`

Called on Pod Add and Update events.

1. Guards via `complianceReady(ready)` — drops events before cache sync
2. Extracts `*corev1.Pod` via `podFromObject()` (handles `DeletedFinalStateUnknown`)
3. Filters to Running pods via `shouldProcessPod()` — skips Pending/Succeeded/Failed/Unknown
4. Calls `buildPodSpecEvents()` to produce one `EnrichedEvent` per container
5. Routes each event through `handleComplianceEvent()`

### `(a *Agent) onNetworkPolicyEvent(ctx context.Context, obj interface{}, ready <-chan struct{})`

Called on NetworkPolicy Add and Update events.

1. Guards via `complianceReady(ready)`
2. Extracts `*networkingv1.NetworkPolicy` via `networkPolicyFromObject()`
3. Queries `K8sClient.CheckNamespaceDefaultDenyPolicy()` to determine if the namespace has a default-deny policy
4. Builds a single `EnrichedEvent` of type `"network_policy_check"` via `buildNetworkPolicyEvent()`
5. Routes through `handleComplianceEvent()`

### `(a *Agent) buildPodSpecEvents(ctx context.Context, pod *corev1.Pod) []*enrichment.EnrichedEvent`

Iterates over all containers in the pod spec, calling `buildPodSpecEventForContainer()` for each. Returns a slice — one event per container, allowing per-container CIS rule evaluation.

### `(a *Agent) buildPodSpecEventForContainer(...) *enrichment.EnrichedEvent`

Builds a fully-populated `EnrichedEvent` of type `"pod_spec_check"` from the pod spec and container definition. This is the most complex function in the file.

**Fields extracted:**

| Category | Fields | Source |
|---|---|---|
| Image | `Image`, `ImageRegistry`, `ImageTag`, `ImagePullPolicy` | container spec |
| Security context | `Privileged`, `RunAsRoot`, `AllowPrivilegeEscalation`, `ReadOnlyRootFilesystem` | container/pod security context with fallback chain |
| Profiles | `SeccompProfile`, `ApparmorProfile`, `SELinuxLevel` | helper functions with container→pod fallback |
| Host namespaces | `HostNetwork`, `HostIPC`, `HostPID` | pod spec |
| Resources | `MemoryLimit`, `CPULimit`, `MemoryRequest`, `CPURequest`, `StorageRequest` | resource requirements |
| SA / RBAC | `ServiceAccount`, `AutomountServiceAccountToken`, `ServiceAccountTokenAge`, `RBACLevel`, `RBACEnforced`, `ServiceAccountPermissions`, `RolePermissionCount`, `RBACPolicyDefined` | K8s API via `K8sClient` |
| Image signals | `ImageScanStatus`, `ImageSigned`, `ImageRegistryAuth` | pod annotations + imagePullSecrets |
| Runtime signals | `VolumeType`, `ContainerRuntime`, `IsolationLevel`, `KernelHardening` | pod annotations + spec |
| Audit | `AuditLoggingEnabled` | pod annotation override → `K8sClient.IsAuditLoggingEnabled()` |
| Owner | `OwnerRef.Kind`, `OwnerRef.Name`, `OwnerRef.UID` | first `OwnerReference` |

**Security context resolution order** (container overrides pod):
```
container.SecurityContext.X  →  pod.Spec.SecurityContext.X  →  default
```

`resolveRunAsRoot()` logic:
- `runAsNonRoot=true` → `RunAsRoot=false`
- `runAsNonRoot=false && runAsUser=nil` → `RunAsRoot=true` (unknown UID, assume root)
- `runAsNonRoot=false && runAsUser=0` → `RunAsRoot=true`
- `runAsNonRoot=false && runAsUser>0` → `RunAsRoot=false`

### `(a *Agent) buildNetworkPolicyEvent(netpol *networkingv1.NetworkPolicy, hasDefaultDeny bool) *enrichment.EnrichedEvent`

Builds a minimal `EnrichedEvent` of type `"network_policy_check"` containing:
- `Kubernetes.Namespace` — the policy's namespace
- `Kubernetes.HasDefaultDenyNetworkPolicy` — whether the namespace has a default-deny policy

CIS rule `CIS_4.6.x` evaluates `HasDefaultDenyNetworkPolicy` to detect missing namespace isolation.

### `(a *Agent) resolveServiceAccount(ctx, pod) *corev1.ServiceAccount`

Fetches the full `ServiceAccount` object for the pod's service account name. Used to resolve `imagePullSecrets` from the service account when the pod itself has none.

Returns `nil` silently on error — missing SA does not block compliance event generation.

---

## Helper Functions

### `podFromObject(obj interface{}) *corev1.Pod`

Type-switches on `*corev1.Pod` and `cache.DeletedFinalStateUnknown`. The latter is returned by the informer when a pod is deleted during a resync — the actual pod object is nested inside.

### `networkPolicyFromObject(obj interface{}) *networkingv1.NetworkPolicy`

Same pattern as `podFromObject` for `*networkingv1.NetworkPolicy`.

### `shouldProcessPod(pod *corev1.Pod) bool`

Returns `true` only when `pod.Status.Phase == corev1.PodRunning`. Skips Pending, Succeeded, Failed, and Unknown pods to avoid noise from non-running workloads.

### `complianceReady(ready <-chan struct{}) bool`

Non-blocking check — returns `true` if the `ready` channel is closed (or nil), `false` otherwise. Prevents any compliance events from being emitted before the informer cache is populated.

### Security context extraction helpers

| Function | Purpose |
|---|---|
| `apparmorProfile(pod, containerName)` | Reads `container.apparmor.security.beta.kubernetes.io/<name>` annotation |
| `securityContextSeccomp(pod, container)` | Container seccomp → pod seccomp |
| `securityContextSELinux(pod, container)` | Container SELinux level → pod SELinux level |
| `securityContextRunAsNonRoot(pod, container)` | Container `RunAsNonRoot` → pod `RunAsNonRoot` → false |
| `securityContextRunAsUser(pod, container)` | Container `RunAsUser` → pod `RunAsUser` → nil |
| `resolveRunAsRoot(runAsNonRoot, runAsUser)` | Determines `RunAsRoot` bool |

### Resource extraction helpers

| Function | Returns |
|---|---|
| `resourceLimits(container)` | `(memoryLimit, cpuLimit)` strings from `Resources.Limits` |
| `resourceRequests(container)` | `(memoryRequest, cpuRequest, storageRequest)` strings from `Resources.Requests` |

### Image parsing helpers

| Function | Example input | Example output |
|---|---|---|
| `parseImageRegistry("docker.io/nginx:1.25")` | → `"docker.io"` |
| `parseImageRegistry("nginx:1.25")` | → `"docker.io"` (default) |
| `parseImageRegistry("registry.k8s.io/pause:3.9")` | → `"registry.k8s.io"` |
| `parseImageTag("nginx:1.25")` | → `"1.25"` |
| `parseImageTag("nginx")` | → `"latest"` |

`parseImageRegistry` detects a registry prefix by checking if the first path component contains a `.` (domain name convention).

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 64–65 | Cache sync gate (`ready` channel) — prevents pre-sync compliance event emissions |
| 81–82 | Running-only pod filter — avoids noise from terminal/pending pods |
| 86–87 | Per-container pod_spec_check events — ensures per-container CIS compliance |
| 113 | `buildPodSpecEvents` — extracts security context for CIS pod_spec_check rules |
| 220 | RBAC context for pod_spec_check — populates CIS 5.x fields with real values |
| 235 | Warn on RBAC fail-open — same one-call-lag pattern as enricher.go |
| 267 | Compliance fields for pod_spec_check — image/volume/kernel signals |
| 326 | Service account lookup for registry auth — CIS_4.3.5 inputs |

---

## Event Types Produced

| `EventType` | Trigger | Key fields evaluated by rules |
|---|---|---|
| `"pod_spec_check"` | Pod Add/Update (Running only) | All `ContainerContext` security fields, RBAC fields in `K8sContext` |
| `"network_policy_check"` | NetworkPolicy Add/Update | `K8sContext.HasDefaultDenyNetworkPolicy` |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/agent/agent.go](./agent.md) | Calls `startComplianceWatchers()`; `handleComplianceEvent()` is defined there |
| [pkg/kubernetes/client.go](../kubernetes/client.md) | `GetServiceAccountMetadata()`, `GetRBACLevel()`, `IsAuditLoggingEnabled()`, etc. |
| [pkg/enrichment/types.go](../enrichment/types.md) | `EnrichedEvent`, `K8sContext`, `ContainerContext` |
| [pkg/rules/engine.go](../rules/engine.md) | Evaluates `pod_spec_check` and `network_policy_check` rules |
