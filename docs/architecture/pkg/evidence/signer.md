# `pkg/evidence/signer.go` — HMAC-SHA256 Signer

**Package:** `evidence`
**Path:** `pkg/evidence/signer.go`
**Lines:** 43

---

## Overview

Provides HMAC-SHA256 signing for evidence payloads before they are encrypted and pushed to the Owl SaaS API. The signing key is base64-encoded and must be at least 32 bytes decoded.

---

## Types

### `Signer`

```go
type Signer struct {
    key []byte  // first 32 bytes of decoded base64 key
}
```

---

## Functions

### `NewSigner(secretKey string) (*Signer, error)`

Decodes `secretKey` from standard base64. Requires at least 32 decoded bytes — only the first 32 are used. Returns an error if decoding fails or the key is too short.

### `Sign(data []byte) string`

Computes `HMAC-SHA256(key, data)` and returns it as a lowercase hex string. Used to sign the JSON event payload before encryption.

### `Verify(data []byte, signature string) bool`

Recomputes the HMAC and compares using `hmac.Equal` (constant-time comparison to prevent timing attacks). Used to verify received payloads.

---

## Related Files

| File | Relationship |
|---|---|
| [cipher.go](./cipher.md) | Encrypts the payload after signing |
| [pkg/agent/agent.go](../agent/agent.md) | Constructs `Signer` from config; uses in push pipeline |
