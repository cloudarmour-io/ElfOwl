# `pkg/kubernetes/pod_fields.go` — Pod Compliance Field Helpers

**Package:** `kubernetes`
**Path:** `pkg/kubernetes/pod_fields.go`
**Lines:** 352

---

## Overview

Stateless helper functions that extract CIS compliance signals from a `*corev1.Pod` object. Called by `getPodMetadata` in `client.go` to populate the compliance-signal fields of `PodMetadata`. Each function targets one or two specific CIS controls.

---

## Exported Functions

### `ImageScanStatusFromPod(pod, containerName) string`

CIS input: `CIS_4.3.4`. Reads `image-scan-status` from pod annotations or labels (container-scoped key checked first). Returns `"unknown"` when not set.

### `ImageSignedFromPod(pod, containerName) (bool, bool)`

CIS input: `CIS_4.3.6`. Reads `image-signed` annotation/label. Returns `(value, true)` when found and parseable; `(false, false)` when absent or unrecognised.

### `ImageRegistryAuthFromPod(pod, containerName, serviceAccount) bool`

CIS input: `CIS_4.3.5`. Priority order:
1. Explicit `image-registry-auth` annotation/label override
2. `pod.Spec.ImagePullSecrets` non-empty
3. `serviceAccount.ImagePullSecrets` non-empty

### `VolumeTypeForContainer(pod, container) string`

CIS input: `CIS_4.8.2`. Iterates `container.VolumeMounts` to collect mounted volume types. Returns the most sensitive type found (priority: `hostPath` > `local` > `emptyDir`) or the first type if none are sensitive.

### `KernelHardeningFromPod(pod) bool`

CIS input: `CIS_4.9.3`. Checks `pod.Spec.SecurityContext.Sysctls` for any of:
- `kernel.dmesg_restrict = "1"`
- `kernel.kptr_restrict = "1"`
- `kernel.yama.ptrace_scope >= 1`

### `ContainerRuntimeFromPod(pod, containerName) string`

CIS input: `CIS_4.9.1`. Priority order:
1. `container-runtime` annotation/label
2. Parse `runtime://containerID` prefix from `ContainerStatuses` (main → init → ephemeral)

Returns `"unknown"` if not determinable.

### `IsolationLevelForContainer(pod, container) int`

CIS input: `CIS_4.9.2`. Returns `0`–`3` based on a weighted score:

| Signal | Weight |
|---|---|
| `RunAsNonRoot` | +2 |
| `AllowPrivilegeEscalation = false` | +1 |
| `ReadOnlyRootFilesystem = true` | +1 |
| Not privileged | +1 |
| Seccomp profile set (not `"unconfined"`) | +1 |
| No host namespace sharing (`HostNetwork`, `HostIPC`, `HostPID` all false) | +1 |

Score → level: ≥6 → 3, ≥4 → 2, ≥2 → 1, else 0. Explicit `container-isolation-level` annotation/label overrides the computed score (clamped 0–3).

### `AuditLoggingEnabledFromPod(pod) (bool, bool)`

CIS input: `CIS_5.5.1`. Reads `audit-logging-enabled` annotation/label. Returns `(false, false)` when absent (caller falls back to `IsAuditLoggingEnabled` cluster detection).

### `ServiceAccountTokenTTLFromPod(pod) int64`

CIS input: `CIS_5.2.2`. Walks `pod.Spec.Volumes` for projected service account token sources. Returns the maximum `expirationSeconds` found (default 3600 when `ExpirationSeconds` is nil). Returns 0 if no projected SA token volumes exist.

---

## Internal Helpers

### `podStringValue(pod, baseKey, containerName) (string, bool)`

Checks annotations then labels for `baseKey`, `baseKey.containerName`, and `baseKey/containerName` (via `annotationKeys`). Returns the first match.

### `podBoolValue(pod, baseKey, containerName) (bool, bool)`

Delegates to `podStringValue` then `parseBoolValue`.

### `annotationKeys(baseKey, containerName) []string`

Returns `[baseKey, baseKey.containerName, baseKey/containerName]`. Supports both dot-qualified and slash-qualified container-specific annotation formats.

### `parseBoolValue(value) (bool, bool)`

Accepts `"true"/"1"/"yes"/"y"/"signed"` → `(true, true)` and `"false"/"0"/"no"/"n"/"unsigned"` → `(false, true)`. Returns `(false, false)` for unrecognised values.

### `volumeSourceType(volume) string`

Maps `corev1.Volume` fields to normalised strings: `hostPath`, `emptyDir`, `persistentVolumeClaim`, `configMap`, `secret`, `projected`, `downwardAPI`, `csi`, `ephemeral`.

### Security context helpers (unexported)

| Helper | Purpose |
|---|---|
| `runAsNonRootForContainer(pod, container)` | Container SecurityContext → pod SecurityContext fallback |
| `privilegeEscalationDisabled(container)` | `AllowPrivilegeEscalation != nil && !*AllowPrivilegeEscalation` |
| `readOnlyRootFS(container)` | `ReadOnlyRootFilesystem != nil && *ReadOnlyRootFilesystem` |
| `privilegedContainer(container)` | `Privileged != nil && *Privileged` |
| `seccompProfileForContainer(pod, container)` | Container → pod SecurityContext fallback |
| `runtimeFromStatuses(statuses, containerName)` | Iterate statuses, parse `runtime://` prefix |
| `runtimeFromContainerID(containerID)` | Split on `"://"`, return lowercased prefix |

---

## Related Files

| File | Relationship |
|---|---|
| [client.go](./client.md) | Calls all exported functions inside `getPodMetadata` |
| [pkg/enrichment/types.go](../enrichment/types.md) | `ContainerContext` fields populated from these signals |
