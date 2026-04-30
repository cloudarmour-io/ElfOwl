# `pkg/api/` — OWL SaaS API Client

**Package:** `api`
**Purpose:** Outbound-only HTTP push client for the OWL SaaS compliance platform and TLS certificate probing utilities.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [client.go](../../../../pkg/api/client.go) | [client.md](./client.md) | Push client — sign, encrypt, gzip, POST to OWL SaaS |
| [tls_certificate.go](../../../../pkg/api/tls_certificate.go) | [tls_certificate.md](./tls_certificate.md) | TLS certificate probing and metadata extraction |

### Test files

| File | What it tests |
|---|---|
| `client_test.go` | `Push`, `PushWithRetry`, `BuildTLSConfig` |
| `tls_certificate_test.go` | `ProbeTLSCertificate`, `CertSHA256FromX509` |

---

## Key Invariant

The `Client` is **push-only**. It sends signed, encrypted, gzip-compressed evidence batches to `POST /api/v1/evidence`. It never receives commands or pulls data.

---

## Wire Format

```
[]BufferedEvent → PushBatch (JSON) → sign → encrypt → EncryptedEnvelope → gzip → POST
```

When `cipher == nil` (dev/test mode), the step produces signed-but-unencrypted JSON directly.

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/evidence/](../../../../pkg/evidence/) | `Signer`, `Cipher`, `BufferedEvent` |
| [pkg/config/](../../../../pkg/config/) | `RetryConfig` |
| [pkg/agent/agent.go](../../../../pkg/agent/agent.go) | Constructs and calls this client |
