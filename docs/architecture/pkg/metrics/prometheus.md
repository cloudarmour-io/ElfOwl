# `pkg/metrics/prometheus.go` — Prometheus Registry

**Package:** `metrics`
**Path:** `pkg/metrics/prometheus.go`
**Lines:** 167

---

## Overview

Defines two registries:

- **`Registry`** — full Prometheus metrics via `promauto`, exposed on `:9090/metrics`
- **`SimpleRegistry`** — lightweight `sync/atomic` fallback for environments without Prometheus

---

## `Registry`

### Fields (all private)

| Field | Type | Metric name | Description |
|---|---|---|---|
| `eventsProcessed` | Counter | `elf_owl_events_processed_total` | Every event that enters the pipeline |
| `violationsFound` | Counter | `elf_owl_violations_found_total` | CIS violations detected (batch-incremented) |
| `eventsBuffered` | Gauge | `elf_owl_events_buffered` | Current buffer depth |
| `pushSuccess` | Counter | `elf_owl_push_success_total` | Successful HTTP pushes to Owl SaaS |
| `pushFailure` | Counter | `elf_owl_push_failure_total` | Failed push attempts |
| `pushLatency` | Histogram | `elf_owl_push_latency_seconds` | Push round-trip time (default buckets) |
| `enrichmentErrors` | Counter | `elf_owl_enrichment_errors_total` | Enrichment pipeline errors |
| `ruleMatchErrors` | Counter | `elf_owl_rule_match_errors_total` | Rule engine errors |
| `hostEventsDiscarded` | Counter | `elf_owl_host_events_discarded_total` | Host events dropped by `kubernetes_only` filter |
| `k8sLookupFailedDiscards` | Counter | `elf_owl_k8s_lookup_failed_discards_total` | Events dropped due to K8s API errors (fail-closed) |

`hostEventsDiscarded` and `k8sLookupFailedDiscards` are kept separate so operators can distinguish true host-process events (non-pod) from transient K8s API failures.

### Methods

| Method | Notes |
|---|---|
| `RecordEventProcessed()` | Increments `eventsProcessed` by 1 |
| `RecordViolationFound()` | Increments `violationsFound` by 1 (single violation) |
| `RecordViolationsFound(n int)` | `Counter.Add(float64(n))` — batch increment; fixes undercounting when a single event matches multiple rules |
| `SetEventsBuffered(count int)` | Sets gauge to current buffer `Count()` |
| `RecordPushSuccess()` / `RecordPushFailure()` | Push outcome counters |
| `RecordPushLatency(seconds float64)` | Histogram observation |
| `RecordEnrichmentError()` | Enrichment error counter |
| `RecordRuleMatchError()` | Rule engine error counter |
| `RecordHostEventDiscarded()` | kubernetes_only filter discard |
| `RecordK8sLookupFailedDiscarded()` | Fail-closed K8s API error discard (PR-23 #7) |

### Key Anchor Comments

| Location | Anchor summary |
|---|---|
| `hostEventsDiscarded` field | Host event discard metric — Filter: K8s-native compliance — Mar 24, 2026 |
| `k8sLookupFailedDiscards` field | Separate from hostEventsDiscarded — K8s API errors vs true host events — PR-23 #7 |
| `RecordViolationsFound` | Batch violation counter — fixes undercounting for multi-violation events — Feb 18, 2026 |

---

## `SimpleRegistry`

```go
type SimpleRegistry struct {
    eventsProcessed int64
    violationsFound int64
}
```

Uses `sync/atomic` for thread-safe increment without any Prometheus dependency. Exposes `RecordEventProcessed()` and `RecordViolationFound()` only. Used in tests or stripped-down deployments.

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/agent/agent.go](../agent/agent.md) | Holds `*Registry`; calls all `Record*` methods |
| [cmd/elf-owl/main.go](../../cmd/elf-owl/main.md) | Registers `promhttp.Handler()` on `:9090/metrics` |
