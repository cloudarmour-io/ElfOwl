# `pkg/config/` — Shared Configuration Types

**Package:** `config`
**Purpose:** Holds types shared across packages to prevent circular imports.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [types.go](../../../../pkg/config/types.go) | [types.md](./types.md) | `RetryConfig` — exponential backoff settings |

---

## Why this package exists

`pkg/api` and `pkg/agent` both need `RetryConfig`. Neither can import the other without creating a cycle. A neutral leaf package with no dependencies resolves this.
