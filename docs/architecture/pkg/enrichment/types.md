# `pkg/enrichment/types.go` — Enriched Event Types

**Package:** `enrichment`
**Path:** `pkg/enrichment/types.go`
**Lines:** ~191

---

## Overview

Defines all data structures that flow through the enrichment pipeline and are ultimately serialised to JSON for the Owl SaaS API. The top-level type is `EnrichedEvent`; every other type in this file is a context sub-struct embedded in it.

---

## `EnrichedEvent`

```go
type EnrichedEvent struct {
    RawEvent   interface{}        // original eBPF struct (interface{} avoids circular import)
    EventType  string             // "process_execution" | "network_connection" | "file_access"
                                  // "capability_usage" | "dns_query" | "tls_client_hello"
                                  // "pod_spec_check" | "network_policy_check"
    Kubernetes *K8sContext
    Container  *ContainerContext
    Process    *ProcessContext    // set for process, file, capability events
    File       *FileContext       // set for file events
    Capability *CapabilityContext // set for capability events
    Network    *NetworkContext    // set for network events
    DNS        *DNSContext        // set for dns events
    TLS        *TLSContext        // set for tls events
    Timestamp  time.Time
    Severity   string
    CISControl string
}
```

`RawEvent interface{}` avoids a direct `pkg/ebpf` import in `pkg/enrichment`. Field extraction uses `reflect` in `enricher.go`.

---

## `K8sContext`

| Field | Type | Description |
|---|---|---|
| `ClusterID` | string | From agent config |
| `NodeName` | string | From agent config / `HOSTNAME` env |
| `Namespace` | string | Pod namespace |
| `PodName` | string | Pod name |
| `PodUID` | string | Pod UID — empty for host events |
| `ServiceAccount` | string | Pod service account name |
| `Image` | string | Full image reference |
| `ImageRegistry` | string | Parsed from `Image` |
| `ImageTag` | string | Parsed from `Image` |
| `Labels` | `map[string]string` | Pod labels |
| `OwnerRef` | `*OwnerReference` | Deployment / DaemonSet owner |
| `AutomountServiceAccountToken` | bool | From SA spec |
| `HasDefaultDenyNetworkPolicy` | bool | Set by network policy check |
| `RBACEnforced` | bool | From `IsRBACAPIEnabled()` |
| `RBACLevel` | int | 0=restricted, 1=standard, 2=elevated, 3=admin |
| `ServiceAccountTokenAge` | int64 | Token age in seconds |
| `ServiceAccountPermissions` | int | Total permission grant count |
| `RBACPolicyDefined` | bool | Any RBAC policy bound to SA |
| `RolePermissionCount` | int | Max permission count across roles |
| `AuditLoggingEnabled` | bool | From K8s audit config |

**`PodUID` is the K8s-only gate**: `ErrNoKubernetesContext` is returned when `PodUID == ""`.

---

## `OwnerReference`

```go
type OwnerReference struct {
    Kind string
    Name string
    UID  string
}
```

---

## `ContainerContext`

| Field group | Fields |
|---|---|
| Identity | `ContainerID`, `ContainerName`, `Runtime`, `Labels` |
| Privilege | `Privileged`, `RunAsRoot`, `AllowPrivilegeEscalation`, `AllowPrivilegeEscalationKnown` |
| Namespace sharing | `HostNetwork`, `HostIPC`, `HostPID` |
| Security profiles | `SeccompProfile`, `ApparmorProfile`, `SELinuxLevel` |
| Image | `ImagePullPolicy`, `ImageScanStatus`, `ImageRegistryAuth`, `ImageSigned` |
| Resources | `MemoryLimit`, `CPULimit`, `MemoryRequest`, `CPURequest`, `StorageRequest` |
| Filesystem | `ReadOnlyFilesystem`, `VolumeType` |
| Runtime security | `IsolationLevel`, `KernelHardening` |

`AllowPrivilegeEscalationKnown` distinguishes "explicitly set to false" from "not set" — important for CIS 4.2.5 evaluation.

---

## `ProcessContext`

| Field | Description |
|---|---|
| `PID`, `ParentPID` | Process and parent process ID |
| `UID`, `GID` | Effective UID/GID |
| `Command` | Short executable name (from `comm` or `Argv`) |
| `Arguments` | Full argument list |
| `Filename` | Executable path being exec'd |
| `ContainerID` | Container ID from cgroup |

`ParentPID` and `Arguments` are supplemented from `/proc/<pid>/stat` and `/proc/<pid>/cmdline` in `enricher.go`.

---

## `FileContext`

| Field | Description |
|---|---|
| `Path` | File path accessed |
| `Operation` | `"write"`, `"read"`, `"chmod"`, `"unlink"` |
| `PID`, `UID` | Process that performed the operation |
| `Mode` | File mode bits (for chmod ops) |
| `FD` | File descriptor number (for write ops) |
| `Sensitive` | True if path matches `sensitivePaths` list |

---

## `CapabilityContext`

| Field | Description |
|---|---|
| `Name` | Capability name (e.g. `"CAP_SYS_ADMIN"`) |
| `Allowed` | Whether the capability check passed |
| `PID`, `UID` | Process |
| `SyscallID` | Syscall that triggered the capability check |

---

## `NetworkContext`

| Field | Description |
|---|---|
| `SourceIP`, `DestinationIP` | IPv4 string form |
| `SourcePort`, `DestinationPort` | uint16 |
| `Protocol` | `"tcp"` or `"udp"` |
| `Direction` | `"inbound"` or `"outbound"` |
| `ConnectionState` | TCP state name |
| `NetworkNamespaceID` | Kernel net namespace inode |
| `IngressRestricted`, `EgressRestricted` | From NetworkPolicy evaluation |
| `NamespaceIsolation` | Namespace has default-deny policy |

---

## `DNSContext`

| Field | Description |
|---|---|
| `QueryName` | FQDN queried |
| `QueryType` | `"A"`, `"AAAA"`, `"MX"`, etc. |
| `ResponseCode` | DNS RCODE integer |
| `QueryAllowed` | Policy evaluation result |
| `AllowedDomains` | Permitted domain list (from rules) |

---

## `TLSContext`

| Field | Description |
|---|---|
| `JA3Fingerprint` | MD5 of JA3 string |
| `JA3String` | `<ver>,<ciphers>,<exts>,<curves>,<pf>` |
| `TLSVersion` | Decimal string of `legacy_version` |
| `Ciphers`, `Extensions`, `Curves` | Parsed lists (GREASE filtered) |
| `PointFormats` | EC point format list |
| `SNI` | Server name from `server_name` extension |
| `CertSHA256` | Colon-hex SHA-256 of leaf cert DER |
| `CertIssuer` | Leaf cert issuer Common Name |
| `CertExpiry` | Leaf cert `NotAfter` as Unix timestamp |

`CertSHA256`, `CertIssuer`, `CertExpiry` are populated by the TLS cert probe in `TLSMonitor` (not by the enricher) and are preserved by `agent.handleTLSEvent` after enrichment.

---

## Type Aliases

```go
type PodMetadata  = kubernetes.PodMetadata
type NodeMetadata = kubernetes.NodeMetadata
```

Re-exported as aliases so callers in `pkg/enrichment` can use `enrichment.PodMetadata` without importing `pkg/kubernetes` directly.

---

## Related Files

| File | Relationship |
|---|---|
| [enricher.go](./enricher.md) | Constructs all context types |
| [pkg/agent/agent.go](../agent/agent.md) | Consumes `EnrichedEvent`; preserves TLS cert fields |
| [pkg/rules/engine.go](../rules/) | Extracts fields from `EnrichedEvent` for rule matching |
| [pkg/evidence/buffer.go](../evidence/buffer.md) | Wraps `EnrichedEvent` for batching |
