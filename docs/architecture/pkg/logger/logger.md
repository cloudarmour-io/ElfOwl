# `pkg/logger/logger.go` — Logger Constructor

**Package:** `logger`
**Path:** `pkg/logger/logger.go`
**Lines:** 38

---

## Overview

Single exported function that creates a `*zap.Logger` configured for the requested level. Switches between production (JSON, no caller info) and development (text, coloured, stack traces) configurations.

---

## Functions

### `NewLogger(level string) (*zap.Logger, error)`

1. `zapcore.ParseLevel(level)` — accepts `"debug"`, `"info"`, `"warn"`, `"error"`, `"dpanic"`, `"panic"`, `"fatal"`. Returns an error for unrecognised strings.
2. If `level == "debug"`: uses `zap.NewDevelopmentConfig()` — text encoder, coloured levels, caller + stack traces.
3. Otherwise: uses `zap.NewProductionConfig()` — JSON encoder, ISO8601 timestamps, no stack traces for non-fatal levels.
4. Overrides `config.Level` with the parsed level before calling `config.Build()`.

---

## Output Formats

| Mode | Condition | Encoder | Fields |
|---|---|---|---|
| Production | any level except `debug` | JSON | timestamp, level, logger, message, fields |
| Development | `level == "debug"` | text (console) | timestamp, level (coloured), caller, message, fields |

---

## Usage

```go
logger, err := logger.NewLogger(cfg.LogLevel)
// logger is *zap.Logger — pass to agent, monitors, enricher
```

---

## Related Files

| File | Relationship |
|---|---|
| [cmd/elf-owl/main.go](../../cmd/elf-owl/main.md) | Calls `NewLogger(cfg.LogLevel)` at bootstrap |
| [pkg/agent/config.go](../agent/config.md) | `AgentConfig.LogLevel` string field |
