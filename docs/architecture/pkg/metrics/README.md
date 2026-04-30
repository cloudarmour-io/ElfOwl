# `pkg/metrics/` — Prometheus Metrics

**Package:** `metrics`
**Purpose:** Prometheus counter/gauge/histogram definitions for the agent, plus a lightweight atomic fallback registry.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [prometheus.go](../../../../pkg/metrics/prometheus.go) | [prometheus.md](./prometheus.md) | `Registry`, `SimpleRegistry`, all metric definitions |

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/agent/agent.go](../agent/agent.md) | Constructs `Registry`; calls `Record*` methods after each event |
| [cmd/elf-owl/main.go](../cmd/elf-owl/main.md) | Exposes `:9090/metrics` via `promhttp.Handler()` |
