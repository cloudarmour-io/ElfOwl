# `cmd/elf-owl/main.go` — Agent Entry Point

**Package:** `main`
**Path:** `cmd/elf-owl/main.go`
**Lines:** ~144
**Added:** Dec 26, 2025 / Updated: Feb 18, 2026

---

## Overview

This is the binary entry point for the `elf-owl` compliance observer agent. It is responsible for:

1. Bootstrapping the structured logger
2. Loading configuration (YAML + environment variables)
3. Constructing the agent with all its subsystems
4. Starting the agent event-processing pipeline
5. Launching optional HTTP servers for health checks and Prometheus metrics
6. Blocking until a shutdown signal is received, then gracefully stopping the agent

There is no business logic here — all domain work is delegated to `pkg/agent`, `pkg/logger`, and standard library HTTP tooling.

---

## Build-Time Variables

| Variable | Default | Description |
|---|---|---|
| `version` | `"0.1.0"` | Semantic version injected at build time via `-ldflags` |
| `buildTime` | `"unknown"` | RFC-3339 timestamp injected at build time |
| `gitCommit` | `"unknown"` | Short git SHA injected at build time |

These are logged on startup so every log stream is self-identifying.

---

## Startup Sequence

```
main()
  │
  ├─ logger.NewLogger("info")          → zapLogger  (fatal on error)
  ├─ agent.LoadConfig()                → config     (fatal on error)
  ├─ agent.NewAgent(config)            → agentInstance (fatal on error)
  ├─ signal.Notify(sigChan, SIGTERM, SIGINT)
  ├─ context.WithCancel(Background())  → ctx, cancel
  ├─ agentInstance.Start(ctx)          (fatal on error)
  │
  ├─ [if config.Agent.Health.Enabled]
  │    └─ goroutine: http.ListenAndServe(healthAddr, healthMux)
  │         └─ GET {healthPath}  → JSON-encoded agent.HealthStatus
  │
  ├─ [if config.Agent.Metrics.Enabled]
  │    └─ goroutine: http.ListenAndServe(metricsAddr, metricsMux)
  │         └─ GET {metricsPath} → promhttp.Handler()
  │
  └─ <-sigChan  (blocks)
       └─ agentInstance.Stop()
```

---

## Functions

### `main()`

**Signature:** `func main()`

The only function in the file. Performs the full startup → run → shutdown lifecycle.

#### Steps

| Step | Code Reference | Notes |
|---|---|---|
| Logger init | `logger.NewLogger("info")` | Hardcoded level `"info"` at startup; config-driven level is applied inside `agent.NewAgent` |
| Config load | `agent.LoadConfig()` | Reads `elf-owl.yaml` and env-var overrides; see `pkg/agent/config.go` |
| Agent create | `agent.NewAgent(config)` | Wires enricher, rule engine, K8s client, evidence pipeline, OWL API client |
| Signal setup | `signal.Notify(sigChan, SIGTERM, SIGINT)` | Handles both Kubernetes pod termination and interactive Ctrl-C |
| Agent start | `agentInstance.Start(ctx)` | Starts eBPF ring-buffer consumer and forwarding goroutines |
| Health server | `http.ListenAndServe(healthAddr, healthMux)` | Gated by `config.Agent.Health.Enabled`; default `:9091/health` |
| Metrics server | `http.ListenAndServe(metricsAddr, metricsMux)` | Gated by `config.Agent.Metrics.Enabled`; default `:9090/metrics` |
| Shutdown | `agentInstance.Stop()` | Drains buffers and closes eBPF maps cleanly |

---

## HTTP Endpoints

### `GET /health` (default `:9091`)

- **Enabled by:** `config.Agent.Health.Enabled`
- **Address:** `config.Agent.Health.ListenAddress` (default `:9091`)
- **Path:** `config.Agent.Health.Path` (default `/health`)
- **Response:** `Content-Type: application/json`, body is JSON-encoded `agent.HealthStatus`
- **Used by:** Kubernetes liveness / readiness probes, operators, monitoring dashboards

**Example response shape** (defined in `pkg/agent/agent.go`):
```json
{
  "healthy": true,
  "uptime": "4h32m10s",
  "eventsProcessed": 18432,
  "lastEventAt": "2026-04-30T12:01:00Z"
}
```

### `GET /metrics` (default `:9090`)

- **Enabled by:** `config.Agent.Metrics.Enabled`
- **Address:** `config.Agent.Metrics.ListenAddress` (default `:9090`)
- **Path:** `config.Agent.Metrics.Path` (default `/metrics`)
- **Handler:** `promhttp.Handler()` — reads from the global Prometheus registry
- **Used by:** Prometheus scrape jobs, Grafana dashboards

---

## External Dependencies

| Import | Purpose |
|---|---|
| `context` | Cancellable root context passed to agent |
| `encoding/json` | JSON-encode health status in HTTP handler |
| `net/http` | Serve health and metrics endpoints |
| `os/signal` | Intercept SIGTERM / SIGINT |
| `syscall` | Signal constants |
| `github.com/prometheus/client_golang/prometheus/promhttp` | Prometheus HTTP handler |
| `go.uber.org/zap` | Structured logging |
| `github.com/udyansh/elf-owl/pkg/agent` | Core agent: config, construction, lifecycle |
| `github.com/udyansh/elf-owl/pkg/logger` | Zap logger factory |

---

## Configuration Fields Referenced

All fields come from the struct returned by `agent.LoadConfig()` → `pkg/agent/config.go`.

| Field path | Used for |
|---|---|
| `config.Agent.ClusterID` | Startup debug log |
| `config.Agent.NodeName` | Startup debug log |
| `config.Agent.OWL.Endpoint` | Startup info log |
| `config.Agent.OWL.Push.BatchSize` | Startup info log |
| `config.Agent.Health.Enabled` | Gate health server |
| `config.Agent.Health.ListenAddress` | Health server bind address |
| `config.Agent.Health.Path` | Health server HTTP path |
| `config.Agent.Metrics.Enabled` | Gate metrics server |
| `config.Agent.Metrics.ListenAddress` | Metrics server bind address |
| `config.Agent.Metrics.Path` | Metrics server HTTP path |

---

## Error Handling

| Failure point | Strategy |
|---|---|
| Logger init fails | `fmt.Fprintf(os.Stderr, ...)` + `os.Exit(1)` (logger not available yet) |
| Config load fails | `zapLogger.Fatal(...)` — exits with code 1 |
| Agent creation fails | `zapLogger.Fatal(...)` — exits with code 1 |
| Agent start fails | `zapLogger.Fatal(...)` — exits with code 1 |
| Health server error | `zapLogger.Error(...)` inside goroutine — non-fatal, agent continues |
| Metrics server error | `zapLogger.Error(...)` inside goroutine — non-fatal, agent continues |
| Agent stop error | `zapLogger.Error(...)` — logged, process exits normally |

Health and metrics servers failing after startup are treated as non-fatal so a port conflict does not take down the whole agent.

---

## Anchor Comments in Source

| Line | Anchor | Summary |
|---|---|---|
| 1–5 | `elf-owl agent entry point` | File-level overview |
| 80–88 | `Health HTTP server` | Why health endpoint was added; no hardcoded fallbacks |
| 109–117 | `Prometheus metrics HTTP server` | Why metrics endpoint was added; no hardcoded fallbacks |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/agent/agent.go](../../../../pkg/agent/agent.go) | `NewAgent`, `Start`, `Stop`, `Health` implementations |
| [pkg/agent/config.go](../../../../pkg/agent/config.go) | `LoadConfig`, all config struct definitions |
| [pkg/logger/logger.go](../../../../pkg/logger/logger.go) | `NewLogger` factory |
| [config/elf-owl.yaml](../../../../config/elf-owl.yaml) | Default runtime configuration |
