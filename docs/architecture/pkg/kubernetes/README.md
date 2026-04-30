# `pkg/kubernetes/` — Kubernetes API Client

**Package:** `kubernetes`
**Purpose:** Read-only Kubernetes API client for pod, node, RBAC, and network policy metadata. Provides a TTL cache, rate limiter, and the `PodMetadata` / `NodeMetadata` types consumed by the enrichment pipeline.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [client.go](../../../../pkg/kubernetes/client.go) | [client.md](./client.md) | `Client` struct, all K8s API methods, data types |
| [cache.go](../../../../pkg/kubernetes/cache.go) | [cache.md](./cache.md) | `MetadataCache` — TTL cache for pod/node/container/cgroup mappings |
| [pod_fields.go](../../../../pkg/kubernetes/pod_fields.go) | [pod_fields.md](./pod_fields.md) | Pod annotation/label helpers for CIS compliance signal extraction |

---

## Architecture

```
NewClient(inCluster)
    │
    ├── rest.InClusterConfig() or kubeconfig
    ├── kubernetes.NewForConfig()
    ├── NewMetadataCache(5min TTL)
    └── rate.NewLimiter(50 rps, burst 100)
           │
           ▼
    Client methods
    ├── GetPodMetadata / GetPodMetadataForContainer / GetPodByContainerID
    ├── GetNodeMetadata
    ├── GetServiceAccountMetadata
    ├── GetRBACLevel / CountRBACPermissions / MaxRolePermissionCount / HasRBACPolicy
    ├── GetNetworkPolicyStatus / CheckNamespaceDefaultDenyPolicy
    ├── IsRBACAPIEnabled / HasSuccessfulRBACProbe
    ├── IsAuditLoggingEnabled
    └── ListAllPods (used for cgroup pre-caching at startup)
```

---

## Key Design Notes

- **Rate limiter** — all API calls go through `waitForAPIBudget`. Default: 50 rps, burst 100. Configurable via `OWL_K8S_API_RATE_LIMIT` / `OWL_K8S_API_BURST` env vars.
- **Memoised probes** — `IsRBACAPIEnabled` (10-min TTL) and `IsAuditLoggingEnabled` (5-min TTL) use write-locked memos to avoid per-event discovery calls.
- **Node-scoped pod list** — `GetPodByContainerID` prefers `spec.nodeName=` field selector over cluster-wide list when `OWL_NODE_NAME` is set, reducing API load significantly.
- **Multi-container support** — `ListAllPods` collects container IDs from all three status arrays (main, init, ephemeral) for complete cgroup mapping coverage.

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/enrichment/enricher.go](../enrichment/enricher.md) | Primary consumer of all `Client` methods |
| [pkg/agent/compliance_watcher.go](../agent/compliance_watcher.md) | Uses `GetPodMetadata` for pod spec compliance events |
