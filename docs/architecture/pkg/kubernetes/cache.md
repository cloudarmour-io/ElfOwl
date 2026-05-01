# `pkg/kubernetes/cache.go` — Metadata Cache

**Package:** `kubernetes`
**Path:** `pkg/kubernetes/cache.go`
**Lines:** 233

---

## Overview

Thread-safe TTL cache for Kubernetes metadata. Stores pod metadata, node metadata, container-ID→pod mappings, and cgroupID→pod mappings. A background goroutine periodically evicts expired entries.

---

## Types

### `MetadataCache`

```go
type MetadataCache struct {
    mu                sync.RWMutex
    pods              map[string]*PodMetadata       // "namespace/podname[#container]" → metadata
    nodes             map[string]*NodeMetadata       // nodeName → metadata
    containerMappings map[string]string              // containerID → "namespace/podname[/container]"
    cgroupMappings    map[uint64]string              // cgroupID → "namespace/podname"
    cgroupExpiry      map[uint64]time.Time           // separate TTL for cgroup entries
    expiry            map[string]time.Time           // TTL for string-keyed entries
    ttlSeconds        int64
    cleanupStop       chan struct{}
    cleanupTicker     *time.Ticker
}
```

`cgroupMappings` has a separate `cgroupExpiry` map because cgroup IDs can be reused after pod restarts. Stale entries must expire to prevent misattribution to old pods (PR-23 #5).

---

## Construction

### `NewMetadataCache(ttlSeconds int64) *MetadataCache`

Creates the cache and starts the background cleanup goroutine. TTL defaults: the cleanup ticker fires at `min(ttl, 10min)`, floor `1min`.

---

## API

### Pod / Node

| Method | Description |
|---|---|
| `GetPod(namespace, name) (*PodMetadata, bool)` | Returns cached pod; miss if expired |
| `SetPod(namespace, name, metadata)` | Stores with TTL expiry |
| `GetNode(nodeName) (*NodeMetadata, bool)` | Returns cached node |
| `SetNode(nodeName, metadata)` | Stores with TTL expiry |

### Container ID Mappings

| Method | Description |
|---|---|
| `GetContainerMapping(containerID) (string, bool)` | Returns `"namespace/pod[/container]"` string |
| `SetContainerMapping(containerID, mapping)` | Stores with TTL expiry |

Cache key format: `"namespace/podname"` or `"namespace/podname/containername"`.

### CgroupID Mappings

| Method | Description |
|---|---|
| `GetCgroupMapping(cgroupID uint64) (string, bool)` | Returns pod mapping; miss if TTL expired |
| `SetCgroupMapping(cgroupID uint64, mapping string)` | Stores with TTL expiry on `cgroupExpiry` |

**TTL expiry on cgroup entries is critical** — cgroup IDs are kernel-assigned integers that get reused when a container restarts with a new cgroup directory. An expired entry must not be returned to avoid attributing a new pod's events to the old pod that previously held that cgroup ID.

### Lifecycle

| Method | Description |
|---|---|
| `Clear()` | Drops all entries; does not stop cleanup goroutine |
| `Close()` | Sends to `cleanupStop`; stops ticker goroutine |
| `Size() int` | Returns `len(pods) + len(nodes)` |

---

## Background Cleanup

`startCleanupLoop` launches a goroutine that calls `cleanupExpired(now)` on each ticker tick. `cleanupExpired` iterates both `expiry` (string keys) and `cgroupExpiry` (uint64 keys) and deletes entries where `now.After(expiry)`.

The double-check pattern (`GetPod` also checks expiry before returning) ensures stale entries are never returned even if the background ticker hasn't fired yet.

---

## Key Anchor Comments

| Location | Anchor summary |
|---|---|
| `cgroupMappings` field | cgroupID→pod mapping — PR-23 #3 `/proc` race fix |
| `GetCgroupMapping` | cgroupMapping TTL expiry — stale cgroup reuse prevention — PR-23 #5 |
| `SetCgroupMapping` | cgroupID→pod cache population — PR-23 #3 |
| `GetContainerMapping` / `SetContainerMapping` | Container ID mapping cache — Phase 2.2 |

---

## Related Files

| File | Relationship |
|---|---|
| [client.go](./client.md) | Creates cache via `NewMetadataCache`; calls all cache methods |
| [pkg/enrichment/enricher.go](../enrichment/enricher.md) | Calls `GetCache()` accessor to set/get cgroup mappings directly |
