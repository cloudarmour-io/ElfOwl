# `pkg/kubernetes/client.go` — Kubernetes API Client

**Package:** `kubernetes`
**Path:** `pkg/kubernetes/client.go`
**Lines:** 1511

---

## Overview

Provides all read-only Kubernetes API access needed by the enrichment pipeline. Wraps `k8s.io/client-go` with a rate limiter, a TTL metadata cache, and memoised cluster-level probes (RBAC API availability, audit logging status).

---

## Types

### `Client`

```go
type Client struct {
    clientset            *kubernetes.Clientset
    config               *rest.Config
    cache                *MetadataCache
    apiLimiter           *rate.Limiter
    discoverServerGroups func() (*metav1.APIGroupList, error)  // injectable for tests
    listKubeSystemPods   func(ctx context.Context) (*corev1.PodList, error)  // injectable
    auditMu              sync.RWMutex
    auditMemo            auditLoggingMemo   // 5-min TTL memo
    rbacMu               sync.RWMutex
    rbacMemo             apiGroupMemo       // 10-min TTL memo
}
```

`discoverServerGroups` and `listKubeSystemPods` are function fields so tests can inject fakes without a live API server.

### Data Types (defined at bottom of file)

| Type | Description |
|---|---|
| `PodMetadata` | Full pod security/resource/compliance context (~40 fields) |
| `NodeMetadata` | Node name, labels, taints, capacity |
| `OwnerReference` | Kind/Name/UID of pod owner (Deployment, DaemonSet, etc.) |
| `ServiceAccountMetadata` | SA name, `AutomountServiceAccountToken`, `TokenCreatedAt` |
| `NetworkPolicyStatus` | `IngressRestricted`, `EgressRestricted`, `NamespaceIsolation` |

---

## Construction

### `NewClient(inCluster bool) (*Client, error)`

- `inCluster=true` → `rest.InClusterConfig()` (pod service account token + CA)
- `inCluster=false` → `clientcmd.BuildConfigFromFlags("", kubeconfig)` — uses `$KUBECONFIG` or `~/.kube/config`
- Cache: `NewMetadataCache(300)` — 5-minute TTL
- Rate limiter: 50 rps / burst 100, overridable via `OWL_K8S_API_RATE_LIMIT` / `OWL_K8S_API_BURST`

---

## Pod Methods

### `GetPodMetadata(ctx, namespace, podName) (*PodMetadata, error)`

Thin wrapper over `getPodMetadata(ctx, namespace, podName, "")`.

### `GetPodMetadataForContainer(ctx, namespace, podName, containerName) (*PodMetadata, error)`

Container-aware wrapper. Extracts security/resource/runtime context from the named container rather than always using `pod.Spec.Containers[0]`.

### `getPodMetadata(ctx, namespace, podName, containerName)` (private)

Full implementation:

1. Check cache (`"namespace/podname#container"` key)
2. `waitForAPIBudget` + `Pods(namespace).Get(podName)`
3. Select target container (by name, fallback to index 0)
4. Extract security context: pod-level → container-level override chain
5. Fetch `ServiceAccount` object (for `imagePullSecrets` detection)
6. Call all `pod_fields.go` helpers (`ImageScanStatusFromPod`, `VolumeTypeForContainer`, etc.)
7. Call `IsAuditLoggingEnabled` if no pod-level audit override
8. Build `PodMetadata`, cache it, return

**Security context precedence:** Container-level `RunAsNonRoot` overrides pod-level. `AllowPrivilegeEscalation` defaults to `true` when not set (K8s default).

### `GetPodByContainerID(ctx, containerID) (*PodMetadata, error)`

Resolves a container ID to pod metadata via a three-tier lookup:

```
1. Cache: GetContainerMapping(containerID)
2. Node-scoped list: Pods("").List(fieldSelector="spec.nodeName=OWL_NODE_NAME")
3. Namespace-scoped list: Pods(AGENT_NAMESPACE).List()
4. Cluster-wide list: Pods("").List()
```

Each tier normalises the container ID (strips `docker://`, `containerd://`, `cri-o://` prefixes) and checks all three container status arrays (main, init, ephemeral) via `findContainerNameForID`.

`AGENT_NAMESPACE` env var (default `"monitoring"`) scopes the fallback list.

### `ListAllPods(ctx) (map[string]*PodMetadata, error)`

Cluster-wide pod list returning `map["namespace/podname"]*PodMetadata`. Populates `ContainerIDs` (all three status arrays) and `ContainerIDToName` on each entry. Used by `refreshCgroupPodMappings` in the enricher at startup.

---

## Node / ServiceAccount Methods

### `GetNodeMetadata(ctx, nodeName) (*NodeMetadata, error)`

Cache-first. Extracts taints as `"key=value:effect"` strings and capacity as `map[resource]string`.

### `GetServiceAccountMetadata(ctx, namespace, saName) (*ServiceAccountMetadata, error)`

Fetches the `ServiceAccount` object. Reads `AutomountServiceAccountToken` (defaults to `true` when unset). If `sa.Secrets` is non-empty, fetches the first secret to get `TokenCreatedAt` (Unix timestamp of secret creation).

---

## RBAC Methods

### `GetRBACLevel(ctx, namespace, saName) int`

Returns `permissionLevelFromCount(CountRBACPermissions(...))`:
- 0 = restricted (0 permissions)
- 1 = standard (1–10)
- 2 = elevated (11–100)
- 3 = admin (>100)

### `CountRBACPermissions(ctx, namespace, saName) int`

Sums verbs across all `Role` and `ClusterRole` objects bound to the service account via `RoleBinding` and `ClusterRoleBinding`. Wildcard verb `"*"` counts as `wildcardVerbWeight = 100`.

### `MaxRolePermissionCount(ctx, namespace, saName) int`

Returns the highest per-role permission count (not total). Used for role granularity checks distinct from aggregate `CountRBACPermissions`.

### `HasRBACPolicy(ctx, namespace, saName) bool`

Returns `CountBoundRoles(...) > 0`.

### `CountBoundRoles(ctx, namespace, saName) int`

Counts distinct `Kind/Name` role references across all bindings.

---

## Cluster Probe Methods

### `IsRBACAPIEnabled(ctx) bool`

Checks `rbac.authorization.k8s.io` in `Discovery().ServerGroups()`. Memoised with 10-minute TTL (`apiGroupMemo`). Fail-open (returns `true`) on transient errors until first successful probe. **Never returns `false` before a confirmed successful probe.**

### `HasSuccessfulRBACProbe() bool`

Returns `rbacMemo.checked` under RLock. `true` only after a successful `serverGroups()` call — never set on fail-open paths. Used by enricher to emit a warn log when `RBACEnforced` state is unverified.

### `IsAuditLoggingEnabled(ctx) bool`

Checks `kube-system` pods for `kube-apiserver` containers with `--audit-log-path`, `--audit-policy-file`, or `--audit-webhook-config-file` flags. Memoised 5-minute TTL. Returns `false` (fail-closed) when no API server pod is found or probe fails.

---

## Network Policy Methods

### `GetNetworkPolicyStatus(ctx, namespace, podName, labels) *NetworkPolicyStatus`

Lists `NetworkPolicies` in the namespace. For each policy matching the pod's labels via `selectorMatches`:
- Counts ingress/egress policies
- Detects default-deny (empty rule list for a given policy type)

Separately scans for namespace-wide default-deny (empty pod selector + empty rules).

### `CheckNamespaceDefaultDenyPolicy(ctx, namespace) bool`

Same default-deny detection logic, namespace-scoped. Used as fallback when pod metadata is unavailable but namespace is known.

### `selectorMatches(labels, selector) bool`

Full `LabelSelector` evaluation:
- `MatchLabels` — direct key=value match
- `MatchExpressions` — `In`, `NotIn`, `Exists`, `DoesNotExist` operators
- Empty selector → matches all pods

**Default-deny requirement:** empty selector alone is insufficient — the policy must also have empty rules for at least one type. Empty selector with allow-all rules is not a deny.

---

## Key Anchor Comments

| Location | Anchor summary |
|---|---|
| `GetPodMetadataForContainer` | Container-specific extraction — multi-container context bleed fix — Mar 29, 2026 |
| `getPodMetadata` AppArmor | Container name in annotation key format |
| `GetPodByContainerID` | Node-scoped list optimisation — O(namespace) before O(cluster) |
| `IsRBACAPIEnabled` | RBAC API detection with memoised TTL — `RBACEnforced` always-true fix |
| `HasSuccessfulRBACProbe` | Distinguishes confirmed vs assumed RBAC state — Apr 20, 2026 |
| `IsAuditLoggingEnabled` | kube-apiserver flags detection — CIS_5.5.1 |
| `GetNetworkPolicyStatus` | Default-deny requires empty selector AND empty rules — Phase 2.4 fix |
| `selectorMatches` | MatchExpressions support — Bug #2 false positives in CIS 4.6.5 |
| `ListAllPods` | All-container ID extraction — PR-23 #6 multi-container mapping |

---

## Related Files

| File | Relationship |
|---|---|
| [cache.go](./cache.md) | `MetadataCache` created and used here |
| [pod_fields.go](./pod_fields.md) | All compliance helper functions called from `getPodMetadata` |
| [pkg/enrichment/enricher.go](../enrichment/enricher.md) | Primary consumer — calls most `Client` methods per event |
| [pkg/agent/compliance_watcher.go](../agent/compliance_watcher.md) | Calls `GetPodMetadata` for compliance watcher events |
