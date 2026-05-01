# `pkg/api/client.go` — OWL SaaS Push Client

**Package:** `api`
**Path:** `pkg/api/client.go`
**Lines:** ~358
**Added:** Dec 26, 2025 / TLS wired: Feb 18, 2026

---

## Overview

Push-only outbound HTTP client for the OWL SaaS compliance platform. The client has one job: take a batch of buffered events, sign them, encrypt them, gzip-compress the result, and POST it to the OWL API endpoint. It never receives commands or pulls data — the invariant is enforced by design.

**Wire format pipeline:**

```
[]BufferedEvent
       │
       ▼
  PushBatch (JSON)
       │
  signer.Sign() → embed Signature → re-marshal
       │
  cipher.Encrypt() → EncryptedEnvelope (ciphertext + nonce, base64)
       │
  gzip compress
       │
  POST /api/v1/evidence
    Headers: Authorization, Content-Encoding: gzip, X-Encrypted, X-Cluster-ID, X-Node-Name
```

---

## Types

### `Client`

| Field | Type | Description |
|---|---|---|
| `endpoint` | string | OWL SaaS base URL |
| `clusterID` | string | Stamped on every push batch |
| `nodeName` | string | Stamped on every push batch |
| `jwtToken` | string | Bearer token for `Authorization` header |
| `httpClient` | `*resty.Client` | HTTP client; TLS config applied if non-nil |
| `logger` | `*zap.Logger` | Production zap logger |
| `signer` | `*evidence.Signer` | HMAC-SHA256 signer; nil = no signing (dev mode) |
| `cipher` | `*evidence.Cipher` | AES-256-GCM cipher; nil = plaintext (dev mode) |
| `tlsConfig` | `*tls.Config` | Applied to resty on construction |
| `retryConfig` | `config.RetryConfig` | Backoff settings for `PushWithRetry` |
| `mu` | `sync.Mutex` | Guards `lastPushTime`, `successCount`, `failureCount` |
| `lastPushTime` | `time.Time` | Updated on each successful push |
| `successCount` | `int64` | Total successful pushes |
| `failureCount` | `int64` | Total push batches that exhausted retries |

### `PushBatch`

Plaintext JSON body, signed before encryption.

| Field | JSON key | Description |
|---|---|---|
| `ClusterID` | `cluster_id` | Source cluster |
| `NodeName` | `node_name` | Source node |
| `Events` | `events` | `[]*evidence.BufferedEvent` |
| `Signature` | `signature` | HMAC-SHA256 of the unsigned batch JSON; empty before signing |
| `SentAt` | `sent_at` | UTC timestamp at push time |

### `EncryptedEnvelope`

Outer wire format when encryption is enabled.

| Field | JSON key | Description |
|---|---|---|
| `Encrypted` | `encrypted` | Always `true` when this struct is used |
| `Ciphertext` | `ciphertext` | base64-encoded AES-256-GCM ciphertext |
| `Nonce` | `nonce` | base64-encoded 12-byte GCM nonce |

---

## Functions

### `NewClient(...) (*Client, error)`

**Parameters:**

| Parameter | Required | Description |
|---|---|---|
| `endpoint` | yes | OWL SaaS base URL |
| `clusterID` | yes | Cluster identifier |
| `nodeName` | yes | Node identifier |
| `jwtToken` | no | Bearer token (warns in push if absent) |
| `signer` | no | nil = skip signing |
| `cipher` | no | nil = skip encryption (dev/test) |
| `tlsCfg` | no | nil = system TLS defaults |
| `retryConfig` | — | Backoff config |

Applies `tlsCfg` to resty via `SetTLSClientConfig`. A nil `tlsCfg` leaves resty using system defaults.

### `BuildTLSConfig(enabled, verify bool, caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error)`

Package-level helper (not a method) that constructs a `*tls.Config` from primitive values. Returns `nil, nil` when `enabled=false` (caller treats nil as system defaults). Called by `agent.go` to avoid a circular import — `api` cannot import `agent`.

**Behaviours:**
- `verify=false` → `InsecureSkipVerify: true` (operator opt-in)
- `caCertPath != ""` → load PEM file, build new cert pool
- `clientCertPath + clientKeyPath != ""` → load X.509 key pair for mTLS

### `Push(ctx, bufferedEvents) error`

Single-attempt push. Steps in order:

1. Marshal `PushBatch` to JSON
2. `signer.Sign(rawJSON)` → embed in `batch.Signature` → re-marshal (sign-then-encrypt)
3. `cipher.Encrypt(signedJSON)` → build `EncryptedEnvelope` → marshal (if cipher non-nil); else use signed JSON directly
4. gzip compress the wire payload
5. POST with headers: `Content-Type: application/json`, `Content-Encoding: gzip`, `Authorization: Bearer <token>`, `X-Cluster-ID`, `X-Node-Name`, `X-Encrypted: true/false`
6. Accept 200 or 202; anything else returns an error

### `PushWithRetry(ctx, bufferedEvents) error`

Wraps `Push()` with exponential backoff using `retryConfig`.

- `InitialBackoff` → doubles each attempt × `BackoffMultiplier`, capped at `MaxBackoff`
- Respects `ctx.Done()` during sleep
- On success: mutex-updates `lastPushTime` and `successCount`
- After `MaxRetries` exhausted: mutex-increments `failureCount`, returns error

### Metric accessors

All three read under `mu`:

| Method | Returns |
|---|---|
| `LastPushTime() time.Time` | Time of last successful push |
| `SuccessCount() int64` | Total successful push batches |
| `FailureCount() int64` | Total batches that exhausted all retries |

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 50–56 | `NewClient` TLS wiring — TLS config was parsed but never applied (Findings Note fix) |
| 104–108 | `BuildTLSConfig` — placed in `api` package to break circular import with `agent` |
| 162–172 | `Push` implementation — was a stub; AES-256-GCM encryption was committed but never called |
| 211–217 | AES-256-GCM encryption step — critical finding fix |
| 295–300 | Mutex-protected success metrics update |
| 325–329 | Mutex-protected failure counter increment |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/api/tls_certificate.go](./tls_certificate.md) | `ProbeTLSCertificate`, `CertSHA256FromX509` — TLS cert probing helpers |
| [pkg/evidence/signer.go](../evidence/) | `evidence.Signer` — HMAC-SHA256 signing |
| [pkg/evidence/cipher.go](../evidence/) | `evidence.Cipher` — AES-256-GCM encryption |
| [pkg/evidence/buffer.go](../evidence/) | `evidence.BufferedEvent` — event type in PushBatch |
| [pkg/config/types.go](../config/types.md) | `config.RetryConfig` |
| [pkg/agent/agent.go](../agent/agent.md) | Calls `NewClient`, `BuildTLSConfig`, `PushWithRetry`, `LastPushTime`, `FailureCount` |
