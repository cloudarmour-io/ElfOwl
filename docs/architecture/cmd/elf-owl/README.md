# `cmd/elf-owl/` — Binary Entry Point

**Package:** `main`
**Purpose:** Compile target for the `elf-owl` agent binary

---

## Directory Contents

| File | Description |
|---|---|
| [main.go](../../../../cmd/elf-owl/main.go) | Agent entry point — logger, config, agent lifecycle, HTTP servers |

---

## Documented Files

| Doc | Source file |
|---|---|
| [main.md](./main.md) | `cmd/elf-owl/main.go` |

---

## Responsibilities

This directory contains **only the wiring layer**. It:

- Initializes the logger and loads configuration
- Constructs the agent via `pkg/agent`
- Starts optional HTTP servers (`/health`, `/metrics`)
- Handles OS signals for graceful shutdown

No domain logic lives here. All compliance, enrichment, and forwarding work is inside `pkg/`.

---

## Default Ports

| Endpoint | Default address | Toggle |
|---|---|---|
| Health | `:9091/health` | `config.Agent.Health.Enabled` |
| Metrics | `:9090/metrics` | `config.Agent.Metrics.Enabled` |

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/agent/](../../../../pkg/agent/) | Core agent construction and lifecycle |
| [pkg/logger/](../../../../pkg/logger/) | Zap logger factory |
| [config/elf-owl.yaml](../../../../config/elf-owl.yaml) | Default runtime configuration |
