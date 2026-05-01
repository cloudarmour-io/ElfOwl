# `pkg/enrichment/` — Event Enrichment Pipeline

**Package:** `enrichment`
**Purpose:** Converts raw eBPF kernel events into `EnrichedEvent` structs with full Kubernetes, container, RBAC, network-policy, and compliance context.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [types.go](../../../../pkg/enrichment/types.go) | [types.md](./types.md) | All enriched event types and context structs |
| [enricher.go](../../../../pkg/enrichment/enricher.go) | [enricher.md](./enricher.md) | `Enricher` struct and all `Enrich*Event` methods |
| [errors.go](../../../../pkg/enrichment/errors.go) | [enricher.md](./enricher.md) | `ErrNoKubernetesContext` sentinel |

---

## Architecture

```
Raw eBPF event (interface{})
       │
       ▼  reflect-based field extraction (no pkg/ebpf import)
Enricher.Enrich*Event()
       │
       ├── procContainerID(pid)      ← /proc/<pid>/cgroup
       ├── getPodMetadata()          ← cgroupID fallback chain
       │       ├── cgroupToContainerCache (local)
       │       ├── containerIDFromCgroupID() ← /sys/fs/cgroup walk
       │       ├── K8sClient cgroup→pod cache
       │       └── refreshCgroupPodMappings() (throttled, 30s)
       │
       ├── K8sClient.GetPodMetadataForContainer()
       ├── K8sClient.GetServiceAccountMetadata()
       ├── K8sClient.GetRBACLevel()
       └── K8sClient.GetNetworkPolicyStatus()
       │
       ▼
EnrichedEvent { Kubernetes, Container, Process/File/Network/DNS/TLS/Capability }
```

---

## Key Design Notes

- **Reflection-based field extraction** — `resolveEventValue`, `fieldUintValue`, `fieldStringValue` read eBPF event struct fields by name using `reflect`. This avoids a circular import (`pkg/enrichment` → `pkg/ebpf` → `pkg/enrichment` via `EnrichedEvent`).
- **`ErrNoKubernetesContext` sentinel** — all `Enrich*` methods return this error (alongside a valid event) when no K8s pod is found. The agent uses `kubernetes_only` config to decide whether to discard.
- **cgroupID fallback chain** — fixes a `/proc` race where a short-lived process exits before `procContainerID` can read `/proc/<pid>/cgroup`. The fallback walks `/sys/fs/cgroup` by inode.
- **2-second K8s timeout** — `enrichmentK8sTimeout = 2s` caps all K8s API calls per event to prevent enrichment backpressure.

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/kubernetes/](../kubernetes/) | `Client` used for all K8s metadata lookups |
| [pkg/ja3/](../ja3/) | `ParseJA3Metadata` called by `EnrichTLSEvent` |
| [pkg/agent/agent.go](../agent/agent.md) | Calls `Enrich*Event`, handles `ErrNoKubernetesContext` |
| [pkg/evidence/](../evidence/) | Consumes `EnrichedEvent` for signing/encryption |
