# `pkg/enrichment/enricher.go` + `errors.go` — Enricher

**Package:** `enrichment`
**Paths:** `pkg/enrichment/enricher.go` (~1545 lines), `pkg/enrichment/errors.go` (5 lines)

---

## Overview

`Enricher` is the core of the enrichment pipeline. It takes a raw eBPF event (`interface{}`), reads fields via reflection, resolves the container and pod identity, queries Kubernetes for security metadata, and returns a fully populated `*EnrichedEvent`.

---

## Types

### `Enricher`

```go
type Enricher struct {
    K8sClient  *kubernetes.Client
    ClusterID  string
    NodeName   string
    Logger     *zap.Logger

    cgroupToContainerMutex sync.RWMutex
    cgroupToContainerCache map[uint64]string  // cgroupID → containerID

    cgroupRefreshMutex sync.Mutex
    lastCgroupRefresh  time.Time
}
```

**Two-level cgroup cache:**
- `cgroupToContainerCache` — local fast cache, populated as events arrive
- `cgroupRefreshMutex` + `lastCgroupRefresh` — throttles expensive `/sys/fs/cgroup` scans to once per 30 seconds

### `ErrNoKubernetesContext` (errors.go)

```go
var ErrNoKubernetesContext = errors.New("no kubernetes pod context: event is not from a pod")
```

Returned by all `Enrich*` methods alongside a valid `*EnrichedEvent` when no K8s pod is found for the event's PID/cgroupID. The agent uses `kubernetes_only` config to decide whether to discard.

---

## Constants

| Constant | Value | Purpose |
|---|---|---|
| `cgroupMappingRefreshInterval` | 30s | Minimum interval between `/sys/fs/cgroup` scan refreshes |
| `enrichmentK8sTimeout` | 2s | Per-event timeout cap for all K8s API calls |

---

## Construction

### `NewEnricher(k8sClient, clusterID, nodeName) (*Enricher, error)`

Creates the enricher and immediately calls `refreshCgroupPodMappings(ctx, force=true)` with a 3-second timeout. This warm-up scan seeds the cgroup cache before the first events arrive, reducing cold-cache misses on startup.

---

## Enrich* Methods

All five `Enrich*Event` methods follow the same structure:

1. Apply `enrichmentK8sTimeout` to ctx (if K8sClient is set)
2. `resolveEventValue(rawEvent)` — reflect-unwrap to struct `Value`
3. Extract fields via `fieldUintValue` / `fieldStringValue` / `fieldBytesValue`
4. `procContainerID(pid)` → container ID from `/proc/<pid>/cgroup`
5. `getPodMetadata(ctx, containerID, cgroupID)` → `*PodMetadata`
6. Populate `K8sContext` and `ContainerContext` from pod metadata
7. Populate event-type-specific context
8. Return event + `ErrNoKubernetesContext` if `k8sCtx.PodUID == ""`

### `EnrichProcessEvent`

Event type: `"process_execution"`. Additional steps:
- `procParentPID(pid)` — reads `/proc/<pid>/stat`
- `procCmdline(pid)` — reads `/proc/<pid>/cmdline` when eBPF args are empty
- RBAC context: `GetServiceAccountMetadata`, `GetRBACLevel`, `CountRBACPermissions`, `MaxRolePermissionCount`, `HasRBACPolicy`
- Security context resolution: `RunAsNonRoot` takes precedence over `RunAsRootContainer` and UID==0

### `EnrichNetworkEvent`

Event type: `"network_connection"`. Additional steps:
- `ipFromUint32` — converts little-endian u32 to dotted-decimal
- `GetNetworkPolicyStatus` — populates `IngressRestricted`, `EgressRestricted`, `NamespaceIsolation`
- `CheckNamespaceDefaultDenyPolicy` — fallback when pod metadata is absent but namespace is known

### `EnrichDNSEvent`

Event type: `"dns_query"`. Straightforward: extracts query name, type, response code, `QueryAllowed`.

### `EnrichTLSEvent`

Event type: `"tls_client_hello"`. Calls `ja3.ParseJA3Metadata(metadata_bytes)`. Returns `TLSContext` with JA3 fields; no K8s lookup (TLS events carry no PID in the current struct). Does **not** return `ErrNoKubernetesContext`.

### `EnrichFileEvent`

Event type: `"file_access"`. `FileEvent` struct has no UID field — uses `procUID(pid)` to read `/proc/<pid>/status`. Uses `procComm(pid)` for `Process.Command` so it is the binary name, not the accessed file path. `isSensitivePath(path)` sets `FileContext.Sensitive`.

### `EnrichCapabilityEvent`

Event type: `"capability_usage"`. Extracts `SyscallID` from the event (previously always 0). Maps capability number to name via `capabilityNameFromID`.

---

## Container / Pod Resolution (`getPodMetadata`)

The full fallback chain for a `(containerID, cgroupID)` pair:

```
1. containerID non-empty?
   └── K8sClient cache: GetContainerMapping(containerID)
       └── hit: GetPodMetadataForContainer(namespace, pod, container)
       └── miss: GetPodByContainerID(containerID)
           └── on success: SetContainerMapping + SetCgroupMapping

2. containerID empty, cgroupID != 0:
   a. cgroupToContainerCache[cgroupID]             (local fast cache)
   b. containerIDFromCgroupID(cgroupID)            (/sys/fs/cgroup inode walk)
   c. resolvePodMetadataFromCgroupMapping(cgroupID) (K8s client cache)
   d. refreshCgroupPodMappings() + retry c          (throttled cold-cache refresh)
```

This chain fixes the `/proc` race condition (PR-23 #3): short-lived processes exit before `/proc/<pid>/cgroup` can be read, but the cgroupID was captured in-kernel at event time and is race-free.

---

## Helper Functions

### `/proc` Readers

| Function | Source | Purpose |
|---|---|---|
| `procCmdline(pid)` | `/proc/<pid>/cmdline` | Full argument list |
| `procParentPID(pid)` | `/proc/<pid>/stat` | Parent PID (field after closing `)`) |
| `procContainerID(pid)` | `/proc/<pid>/cgroup` | Container ID from cgroup path |
| `procUID(pid)` | `/proc/<pid>/status` | Real UID (FileEvent has no UID field) |
| `procComm(pid)` | `/proc/<pid>/comm` | Short binary name |

**TOCTOU note:** All `/proc` reads happen after event delivery to userspace. For processes that exec and exit in <1ms, the PID may be reused. This is an inherent limitation of userspace `/proc` enrichment; in-kernel attribution at event time would require more complex eBPF state.

### Container ID Normalisation

```
normalizeContainerIDSegment(seg)
    → strips .scope, docker-, containerd-, cri-containerd-, crio-, cri-o-, libpod- prefixes
    → validates hex string ≥ 32 chars

containerIDFromPath(path)
    → splits cgroup path by "/" and normalises each segment

normalizeContainerIDValue(value)
    → handles "runtime://containerID" format
    → delegates to containerIDFromPath for path-style values
```

### cgroup → ContainerID Resolution

```
containerIDFromCgroupID(cgroupID)
    → filepath.WalkDir("/sys/fs/cgroup")
    → matches inode (Stat_t.Ino == cgroupID)
    → extracts container ID from matching directory path

scanCgroupContainerMappings()
    → walks /sys/fs/cgroup
    → returns map[containerID]cgroupID (inode)
    → used by refreshCgroupPodMappings

refreshCgroupPodMappings(ctx, force)
    → throttled by cgroupMappingRefreshInterval (30s)
    → calls scanCgroupContainerMappings + ListAllPods
    → registers all container IDs per pod (multi-container fix, PR-23 #6)
    → calls SetContainerMapping + SetCgroupMapping on K8s client cache
```

### Reflection Helpers

| Function | Purpose |
|---|---|
| `resolveEventValue(raw)` | Unwrap pointer, assert struct kind |
| `fieldUintValue(v, name)` | Read uint field by name (handles int kinds too) |
| `fieldStringValue(v, name)` | Read string or `[N]byte` field by name |
| `fieldBytesValue(v, name)` | Read `[]byte` or `[N]byte` field by name |

### Name Lookup Tables

| Function | Map source |
|---|---|
| `dnsQueryTypeName(qtype)` | `dnsQueryTypeNames` (16 entries) |
| `dnsResponseCodeName(rcode)` | `dnsResponseCodeNames` (11 entries) |
| `capabilityNameFromID(id)` | `capabilityNames` (39 entries, CAP_CHOWN–CAP_CHECKPOINT_RESTORE) |
| `fileOperationName(op)` | inline switch: 1=write, 2=read, 3=chmod, 4=unlink |
| `protocolName(proto)` | inline switch: 6=tcp, 17=udp |
| `networkDirectionName(dir)` | inline switch: 1=outbound, 2=inbound |
| `tcpConnectionStateName(state)` | inline switch: 12 TCP states |

### `isSensitivePath(path) bool`

Checks whether `path` equals or is nested under any of 16 hardcoded sensitive paths (`/etc/passwd`, `/etc/shadow`, `/etc/kubernetes`, `/var/run/secrets/kubernetes.io`, etc.). Sets `FileContext.Sensitive`.

---

## Key Anchor Comments

| Location | Anchor summary |
|---|---|
| `Enricher` fields | cgroupID→containerID cache — PR-23 #3 `/proc` race fix |
| `Enricher` fields | cgroup refresh guard — throttles cold-cache scan |
| `getPodMetadata` | CgroupID fallback lookup chain — PR-23 #3 |
| `refreshCgroupPodMappings` | Multi-container cgroup mapping — PR-23 #6 |
| `EnrichProcessEvent` | RBAC fail-open warning — probe not yet confirmed |
| `EnrichNetworkEvent` | Default deny policy flag — CIS_4.6.1 false positive fix |
| `EnrichFileEvent` | Field extraction bug fix — UID/Mode/cmdVal/Sensitive — Apr 29, 2026 |
| `procUID` / `procComm` | TOCTOU known limitation — PID reuse for short-lived processes |
| `sensitivePaths` | Sensitive path list — FileContext.Sensitive was never set fix |
| `EnrichTLSEvent` | pkg/ja3 refactor — eliminated local JA3 duplication |

---

## Related Files

| File | Relationship |
|---|---|
| [types.go](./types.md) | All enriched event types populated here |
| [pkg/kubernetes/client.go](../kubernetes/) | All K8s API calls |
| [pkg/ja3/parser.go](../ja3/parser.md) | `ParseJA3Metadata` called by `EnrichTLSEvent` |
| [pkg/agent/agent.go](../agent/agent.md) | Calls `Enrich*Event`, handles `ErrNoKubernetesContext` |
