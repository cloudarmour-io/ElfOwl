# `pkg/config/types.go` — Shared Configuration Types

**Package:** `config`
**Path:** `pkg/config/types.go`
**Lines:** ~14
**Added:** Dec 26, 2025

---

## Overview

Single-purpose package that holds configuration types shared between multiple packages to prevent circular imports. Currently contains one type: `RetryConfig`.

This package exists only because `pkg/api` needs `RetryConfig` and `pkg/agent` also needs it — putting it in either package would create a circular dependency.

---

## Types

### `RetryConfig`

Exponential backoff settings used by `api.Client.PushWithRetry`.

| Field | Type | Description |
|---|---|---|
| `MaxRetries` | `int` | Maximum number of push attempts (default: 10) |
| `InitialBackoff` | `time.Duration` | Wait after first failure (default: 1 s) |
| `MaxBackoff` | `time.Duration` | Upper cap on backoff duration (default: 60 s) |
| `BackoffMultiplier` | `float64` | Multiplier applied each attempt (default: 2.0) |

**Backoff formula:**

```
backoff[0] = InitialBackoff
backoff[n] = min(backoff[n-1] * BackoffMultiplier, MaxBackoff)
```

With defaults: 1s → 2s → 4s → 8s → 16s → 32s → 60s → 60s → 60s → 60s (10 attempts total).

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/agent/config.go](../agent/config.md) | Embeds `RetryConfig` as `OWLConfig.Retry` |
| [pkg/api/client.go](../api/client.md) | Uses `RetryConfig` in `PushWithRetry` |
