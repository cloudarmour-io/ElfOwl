# `pkg/evidence/` — Evidence Processing

**Package:** `evidence`
**Purpose:** Provides sign-then-encrypt processing for enriched events before they are pushed to the Owl SaaS API, plus an in-memory buffer for batching.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [signer.go](../../../../pkg/evidence/signer.go) | [signer.md](./signer.md) | HMAC-SHA256 event signing |
| [cipher.go](../../../../pkg/evidence/cipher.go) | [cipher.md](./cipher.md) | AES-256-GCM encryption/decryption |
| [buffer.go](../../../../pkg/evidence/buffer.go) | [buffer.md](./buffer.md) | Thread-safe event batch buffer |

---

## Pipeline

```
EnrichedEvent + Violations
       │
       ▼
  Buffer.Enqueue()
       │  (IsFull() or IsStale() triggers flush)
       ▼
  Buffer.Flush()  → []*BufferedEvent
       │
       ▼
  Signer.Sign(JSON)       ← HMAC-SHA256 over JSON body
       │
       ▼
  Cipher.Encrypt(JSON)    ← AES-256-GCM, random nonce
       │
       ▼
  pkg/api Client.Push()   ← gzip + HTTP POST
```

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/enrichment/](../enrichment/) | `EnrichedEvent` type consumed by `Buffer` |
| [pkg/rules/](../rules/) | `Violation` type carried in `BufferedEvent` |
| [pkg/api/](../api/) | `Client.Push()` sends the encrypted payload |
| [pkg/agent/](../agent/) | Orchestrates flush-sign-encrypt-push cycle |
