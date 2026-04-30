# `pkg/agent/` — Core Agent Package

**Package:** `agent`
**Purpose:** Owns the full lifecycle of the elf-owl compliance agent — configuration, orchestration, K8s compliance watching, and outbound event pushing.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [agent.go](../../../../pkg/agent/agent.go) | [agent.md](./agent.md) | Central orchestrator — structs, lifecycle, event routing, rule hot-reload |
| [config.go](../../../../pkg/agent/config.go) | [config.md](./config.md) | All config structs, YAML loading, env overrides, validation |
| [webhook.go](../../../../pkg/agent/webhook.go) | [webhook.md](./webhook.md) | Outbound webhook pusher — batching, HTTP POST, TLS, wire format types |
| [compliance_watcher.go](../../../../pkg/agent/compliance_watcher.go) | [compliance_watcher.md](./compliance_watcher.md) | K8s informer-based compliance events (pod_spec_check, network_policy_check) |

### Test files (not separately documented)

| File | What it tests |
|---|---|
| `agent_init_test.go` | `NewAgent()` construction paths |
| `compliance_watcher_test.go` | `buildPodSpecEvents`, `onPodEvent`, `onNetworkPolicyEvent` |
| `handler_behavior_test.go` | `handleRuntimeEvent` branching (host discard, K8s fail-closed) |
| `handler_runtime_test.go` | Full pipeline integration tests |
| `rule_reload_watcher_test.go` | `watchRuleUpdates` hot-reload logic |
| `webhook_pusher_test.go` | `WebhookPusher` batching, TLS, retry, drain |

---

## Event Pipeline Summary

```
eBPF monitors ──→ handle{Process,Network,DNS,File,Capability,TLS}Events()
                        │
                        ▼
              handleRuntimeEvent()   (enrichment + rule eval + routing)
                        │
             ┌──────────┴──────────────┐
             ▼                         ▼
     EventBuffer.Enqueue()     WebhookPusher.Send()
     (→ OWL SaaS via pushEvents)  (→ ClickHouse ingest)

K8s informers ──→ startComplianceWatchers()
                        │
                        ▼
              handleComplianceEvent()  (rule eval + routing)
```

---

## Key Interfaces

| Interface | Implemented by | Used by |
|---|---|---|
| `EnrichmentProvider` | `enrichment.Enricher` | `agent.go` — injected at construction, allows test fakes |
| `MetricsRecorder` | `metrics.Registry` | `agent.go` — injected at construction, allows test fakes |

---

## Configuration Entry Points

| Function | Returns |
|---|---|
| `LoadConfig()` | `*Config` — reads YAML + env overrides + validates |
| `DefaultConfig()` | `*Config` — safe baseline used as merge target |

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/ebpf/](../../../../pkg/ebpf/) | eBPF monitor types consumed by agent |
| [pkg/enrichment/](../../../../pkg/enrichment/) | Implements `EnrichmentProvider` |
| [pkg/rules/](../../../../pkg/rules/) | CIS rule engine |
| [pkg/evidence/](../../../../pkg/evidence/) | Signer, Cipher, Buffer |
| [pkg/api/](../../../../pkg/api/) | OWL SaaS push client |
| [pkg/kubernetes/](../../../../pkg/kubernetes/) | K8s metadata client |
| [pkg/metrics/](../../../../pkg/metrics/) | Prometheus registry |
