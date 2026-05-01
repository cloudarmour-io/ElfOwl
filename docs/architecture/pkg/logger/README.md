# `pkg/logger/` — Structured Logging

**Package:** `logger`
**Purpose:** Single-function wrapper around `go.uber.org/zap` that configures production JSON logging or development text logging based on the configured level.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [logger.go](../../../../pkg/logger/logger.go) | [logger.md](./logger.md) | `NewLogger` constructor |

---

## Related Packages

| Package | Role |
|---|---|
| [cmd/elf-owl/main.go](../cmd/elf-owl/main.md) | Calls `NewLogger(cfg.LogLevel)` at startup |
| [pkg/agent/agent.go](../agent/agent.md) | Receives `*zap.Logger`; passes it to monitors and enricher |
