# `pkg/agent/agent.go` — Core Agent Orchestrator

**Package:** `agent`
**Path:** `pkg/agent/agent.go`
**Lines:** ~1174
**Added:** Dec 26, 2025 / Migrated to cilium/ebpf: Dec 27, 2025

---

## Overview

The primary orchestrator for the entire `elf-owl` compliance pipeline. It owns the full lifecycle of every subsystem — eBPF monitors, the enrichment engine, the rule engine, the evidence pipeline, the OWL API client, and the outbound webhook pusher — and routes events through the chain:

```
cilium/ebpf kernel events
        │
        ▼
  eBPF Monitor  (ProcessMonitor / NetworkMonitor / ...)
        │
        ▼
  handleXxxEvent()   ← per-event-type dispatcher
        │
        ▼
  handleRuntimeEvent()   ← shared enrichment + rule evaluation path
        │
     ┌──┴──────────────────────────────────┐
     │                                     │
     ▼                                     ▼
  EventBuffer.Enqueue()           WebhookPusher.Send()
  (→ OWL SaaS API)                (→ ClickHouse ingest)
```

K8s compliance events (pod specs, network policies) bypass the eBPF path and are injected directly via `handleComplianceEvent()`.

---

## Interfaces

### `EnrichmentProvider`

```go
type EnrichmentProvider interface {
    EnrichProcessEvent(ctx, rawEvent) (*EnrichedEvent, error)
    EnrichNetworkEvent(ctx, rawEvent) (*EnrichedEvent, error)
    EnrichDNSEvent(ctx, rawEvent) (*EnrichedEvent, error)
    EnrichFileEvent(ctx, rawEvent) (*EnrichedEvent, error)
    EnrichCapabilityEvent(ctx, rawEvent) (*EnrichedEvent, error)
    EnrichTLSEvent(ctx, rawEvent) (*EnrichedEvent, error)
}
```

Implemented by `enrichment.Enricher`. Defined here as an interface so tests can inject fakes.

### `MetricsRecorder`

```go
type MetricsRecorder interface {
    RecordEventProcessed()
    RecordViolationsFound(n int)
    RecordEnrichmentError()
    RecordHostEventDiscarded()
    RecordK8sLookupFailedDiscarded()
    SetEventsBuffered(count int)
}
```

Implemented by `metrics.Registry`. Defined here so tests can inject a no-op recorder.

---

## Types

### `Agent`

The central struct. All public fields are set once in `NewAgent()` and read-only thereafter except those guarded by mutexes.

| Field | Type | Description |
|---|---|---|
| `Config` | `*Config` | Full runtime configuration |
| `Logger` | `*zap.Logger` | Structured logger |
| `ProcessMonitor` | `*ebpf.ProcessMonitor` | eBPF process events |
| `NetworkMonitor` | `*ebpf.NetworkMonitor` | eBPF network events |
| `DNSMonitor` | `*ebpf.DNSMonitor` | eBPF DNS events |
| `TLSMonitor` | `*ebpf.TLSMonitor` | eBPF TLS client hello events |
| `FileMonitor` | `*ebpf.FileMonitor` | eBPF file access events |
| `CapabilityMonitor` | `*ebpf.CapabilityMonitor` | eBPF Linux capability events |
| `K8sClient` | `*kubernetes.Client` | K8s API client; nil when `kubernetes_metadata=false` |
| `RuleEngine` | `*rules.Engine` | CIS rule evaluator; swapped atomically on hot-reload |
| `Enricher` | `EnrichmentProvider` | Adds K8s context to raw eBPF events |
| `Signer` | `*evidence.Signer` | HMAC-SHA256 event signing |
| `Cipher` | `*evidence.Cipher` | AES-256-GCM event encryption |
| `APIClient` | `*api.Client` | OWL SaaS push client |
| `EventBuffer` | `*evidence.Buffer` | Batch buffer for OWL API push |
| `WebhookPusher` | `*WebhookPusher` | Outbound ClickHouse pusher; nil when disabled |
| `MetricsRegistry` | `MetricsRecorder` | Prometheus counter wrappers |
| `ruleMu` | `sync.RWMutex` | Guards `RuleEngine` field during hot-reload |
| `metricsMutex` | `sync.Mutex` | Guards `eventsProcessed` / `violationsFound` counters |
| `producerWg` | `sync.WaitGroup` | Tracks producer goroutines for graceful shutdown ordering |
| `cancelProducers` | `context.CancelFunc` | Cancels producer child context on `Stop()` |
| `done` | `chan struct{}` | Closed by `Stop()` to signal all goroutines |
| `startTime` | `time.Time` | Used to compute uptime in `Health()` |

### `HealthStatus`

```go
type HealthStatus struct {
    AgentVersion     string
    Uptime           time.Duration
    Monitors         map[string]bool   // "process", "network", "dns", "file", "capability"
    EventsProcessed  int64
    ViolationsFound  int64
    LastPushTime     time.Time
    PushFailureCount int64
    Status           string            // always "healthy" currently
}
```

Returned by `Health()` and JSON-encoded on `GET /health`.

---

## Functions

### `NewAgent(config *Config) (*Agent, error)`

Constructs and wires all subsystems. Does **not** start goroutines or attach eBPF programs — that happens in `Start()`.

**Construction order:**

1. `logger.NewLogger(config.Agent.Logging.Level)` — zap logger at configured level
2. `kubernetes.NewClient(inCluster)` — K8s client (skipped when `kubernetes_metadata=false`)
3. `rules.NewEngineWithConfig(engineConfig)` — CIS rule engine with fallback chain: file → ConfigMap → hardcoded
4. `enrichment.NewEnricher(k8sClient, clusterID, nodeName)` — enrichment pipeline
5. `evidence.NewSigner(signingKey)` — HMAC signing; key from env → secret file → ephemeral
6. `evidence.NewCipher(encryptionKey)` — AES-256-GCM; key from env → secret file → ephemeral
7. `evidence.NewBuffer(batchSize, batchTimeout)` — push buffer
8. `api.BuildTLSConfig(...)` → `api.NewClient(...)` — OWL API client with TLS config
9. `NewWebhookPusher(...)` — created only when `webhook.enabled=true`

### `Start(ctx context.Context) error`

Loads eBPF programs, constructs monitors, and launches all goroutines.

**Goroutines started:**

| Goroutine | Count | Context | Exits on |
|---|---|---|---|
| `handleProcessEvents` | 1 | `producerCtx` | `done` or ctx cancel |
| `handleNetworkEvents` | 1 | `producerCtx` | `done` or ctx cancel |
| `handleDNSEvents` | 1 | `producerCtx` | `done` or ctx cancel |
| `handleFileEvents` | 1 | `producerCtx` | `done` or ctx cancel |
| `handleCapabilityEvents` | 1 | `producerCtx` | `done` or ctx cancel |
| `handleTLSEvents` | 1 | `producerCtx` | `done` or ctx cancel |
| `startComplianceWatchers` | 0 or 1 | `producerCtx` | ctx cancel |
| `watchRuleUpdates` | 1 | outer `ctx` | `done` or ctx cancel |
| `pushEvents` | 0 or 1 | outer `ctx` | `done` or ctx cancel |
| `collectMetrics` | 1 | outer `ctx` | `done` or ctx cancel |

The 6 eBPF handlers + compliance watcher are tracked by `producerWg` so `Stop()` can drain them before shutting down `WebhookPusher`.

### `Stop() error`

Graceful shutdown in order:

1. `close(done)` — unblocks all `<-a.done` selects
2. `cancelProducers()` — signals compliance watcher to exit
3. `producerWg.Wait()` — blocks until all 7 producer goroutines return
4. Stops each non-nil eBPF monitor (`ProcessMonitor.Stop()` etc.)
5. `WebhookPusher.Stop()` — drains and flushes the outbound channel
6. Returns joined errors from monitor Stop calls

### `Health() HealthStatus`

Reads `eventsProcessed` and `violationsFound` under `metricsMutex`. Queries `APIClient.LastPushTime()` and `APIClient.FailureCount()`. Returns a populated `HealthStatus`.

### `handleRuntimeEvent(...)` (shared pipeline)

Central enrichment + rule evaluation path called by all 6 eBPF event handlers.

**Parameters:**
- `rawEnriched` — partially-populated event from the eBPF monitor
- `enrichFn` — the specific `EnrichXxxEvent` method to call
- `hostDiscardMsg`, `hostProcessMsg` — log messages for the `ErrNoKubernetesContext` branch
- `apiDiscardMsg`, `apiFallbackMsg` — log messages for other enrichment errors
- `logViolationDetails` — whether to log per-violation detail (true only for process events)

**Decision tree:**

```
enrichFn(ctx, rawEvent)
  ├─ OK → continue with enriched event
  ├─ ErrNoKubernetesContext (host process, no pod):
  │    ├─ kubernetes_only=true  → discard + RecordHostEventDiscarded()
  │    └─ kubernetes_only=false → proceed with rawEnriched
  └─ other error (K8s API failure):
       ├─ kubernetes_only=true  → discard + RecordK8sLookupFailedDiscarded()
       └─ kubernetes_only=false → proceed with rawEnriched

ruleEngine.Match(event)
  → increment counters
  → log violations (if logViolationDetails)

EventBuffer.Enqueue(event, violations)
WebhookPusher.Send(event, violations)   ← if non-nil
```

### Per-monitor dispatch functions

| Function | Enricher called | Violation logging |
|---|---|---|
| `handleProcessEvent` | `EnrichProcessEvent` | yes |
| `handleNetworkEvent` | `EnrichNetworkEvent` | no |
| `handleDNSEvent` | `EnrichDNSEvent` | no |
| `handleFileEvent` | `EnrichFileEvent` | no |
| `handleCapabilityEvent` | `EnrichCapabilityEvent` | no |
| `handleTLSEvent` | `enrichWithCert` wrapper → `EnrichTLSEvent` | no |

The TLS handler wraps the enricher to preserve `CertSHA256`, `CertIssuer`, and `CertExpiry` fields that the TLS monitor probed asynchronously — these would otherwise be overwritten by `EnrichTLSEvent` re-parsing the raw bytes.

### Loop goroutines

| Function | Trigger | Purpose |
|---|---|---|
| `handleXxxEvents` | channel receive from monitor | Route eBPF events to pipeline |
| `handleComplianceEvent` | called by `startComplianceWatchers` | Route K8s API events to same pipeline |
| `pushEvents` | ticker (`BatchTimeout`) | Flush `EventBuffer` to OWL API |
| `watchRuleUpdates` | ticker (30 s) | Hot-reload rule engine from file/ConfigMap |
| `collectMetrics` | ticker (30 s) | Refresh Prometheus buffer gauge |

### Rule engine helpers

| Function | Purpose |
|---|---|
| `getRuleEngine()` | RLock-protected read of `RuleEngine` field |
| `setRuleEngine(engine)` | Lock-protected swap of `RuleEngine` field |
| `ruleEngineSignature(engine)` | SHA-256 of JSON-marshalled rules; used to detect reload changes |
| `ruleEngineConfig(ctx)` | Builds `rules.EngineConfig` from agent config |
| `watchRuleUpdates(ctx)` | 30 s poll; reloads only when signature changes |
| `effectiveRuleReloadInterval()` | Returns configured interval or constant fallback (30 s) |
| `effectiveRuleReloadTimeout()` | Returns configured timeout or constant fallback (10 s) |

### Credential helpers

| Function | Resolution order |
|---|---|
| `getSigningKey()` | `ELF_OWL_SIGNING_KEY` env → `/var/run/secrets/elf-owl-signing-key` → ephemeral |
| `getEncryptionKey()` | `ELF_OWL_ENCRYPTION_KEY` env → `/var/run/secrets/elf-owl-encryption-key` → ephemeral |
| `getJWTToken()` | `OWL_JWT_TOKEN` env → `config.Agent.OWL.Auth.TokenPath` file → empty (warns) |

All file reads use `strings.TrimSpace()` to strip the trailing newline that Kubernetes secret volume mounts append.

### `violationPodName(v *rules.Violation) string`

Nil-safe accessor. `v.Pod` (`= event.Kubernetes`) can be nil when K8s lookup failed. Returns `""` in that case rather than panicking.

### `generateEphemeralKey() (string, error)`

Generates 32 random bytes, base64-encodes them. Used as a fallback when neither env var nor secret file provides signing/encryption keys. Logs a warning — ephemeral keys mean loss of identity across restarts.

---

## Concurrency Model

```
                     ┌─ handleProcessEvents ─┐
                     ├─ handleNetworkEvents  ─┤
eBPF monitor chans   ├─ handleDNSEvents      ─┼─→ handleRuntimeEvent()
(one per monitor)    ├─ handleFileEvents     ─┤     │
                     ├─ handleCapabilityEvents┤     ├─→ EventBuffer  (Enqueue is mutex-protected)
                     └─ handleTLSEvents      ─┘     └─→ WebhookPusher.Send() (channel, non-blocking)

K8s informer         └─ startComplianceWatchers ──→ handleComplianceEvent()

All above tracked by producerWg (7 goroutines when K8sClient != nil, 6 otherwise)
```

`eventsProcessed` and `violationsFound` are protected by `metricsMutex` because all 6-7 goroutines write them concurrently.

`RuleEngine` is protected by `ruleMu` (RWMutex) because `watchRuleUpdates` swaps it while handlers read it.

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 94–102 | `producerWg` / `cancelProducers` — shutdown ordering for webhook pusher drain |
| 142 | Monitors created in `Start()`, not `NewAgent()`, to avoid partially-initialized state |
| 146 | Optional K8s client bootstrap — skipped when `kubernetes_metadata=false` |
| 228 | TLS config built from operator YAML and applied to OWL API client |
| 404 | Producer goroutines tracked before launch |
| 466 | `ErrNoKubernetesContext` handling — fail-closed when `kubernetes_only=true` |
| 480 | K8s API errors fail-closed to prevent false positives during outages |
| 622 | TLS cert field preservation wrapper — prevents `EnrichTLSEvent` from losing cert probe data |
| 994 | Shutdown ordering: cancel producers → wait → stop pusher |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/agent/config.go](./config.md) | `Config`, `LoadConfig`, `DefaultConfig` |
| [pkg/agent/webhook.go](./webhook.md) | `WebhookPusher`, `WebhookEvent`, all webhook types |
| [pkg/agent/compliance_watcher.go](./compliance_watcher.md) | K8s informer compliance event source |
| [pkg/enrichment/enricher.go](../enrichment/enricher.md) | Implements `EnrichmentProvider` |
| [pkg/rules/engine.go](../rules/engine.md) | `rules.Engine.Match()` |
| [pkg/evidence/](../evidence/) | `Signer`, `Cipher`, `Buffer` |
| [pkg/api/client.go](../api/client.md) | `api.Client.PushWithRetry()` |
| [pkg/ebpf/](../ebpf/) | All eBPF monitor types |
| [pkg/metrics/prometheus.go](../metrics/prometheus.md) | Implements `MetricsRecorder` |
