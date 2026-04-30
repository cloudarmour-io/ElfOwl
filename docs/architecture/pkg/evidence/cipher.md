# `pkg/evidence/cipher.go` — AES-256-GCM Cipher

**Package:** `evidence`
**Path:** `pkg/evidence/cipher.go`
**Lines:** 80

---

## Overview

Provides AES-256-GCM authenticated encryption for evidence payloads. The key must be exactly 32 bytes (256 bits) decoded from base64.

---

## Types

### `Cipher`

```go
type Cipher struct {
    key []byte  // exactly 32 bytes
}
```

---

## Functions

### `NewCipher(secretKey string) (*Cipher, error)`

Decodes `secretKey` from standard base64. Requires **exactly** 32 bytes — AES-256 has no flexibility on key size. Returns an error if decoding fails or length is not 32.

### `Encrypt(plaintext []byte) (ciphertext, nonce []byte, err error)`

1. Creates `aes.NewCipher(key)` → `cipher.NewGCM(block)`
2. Generates a random nonce via `io.ReadFull(rand.Reader, ...)` sized to `gcm.NonceSize()` (12 bytes for GCM)
3. `gcm.Seal(nil, nonce, plaintext, nil)` — ciphertext includes the 16-byte GCM authentication tag appended
4. Returns `ciphertext` and `nonce` separately — the caller is responsible for transmitting both

### `Decrypt(ciphertext, nonce []byte) (plaintext []byte, err error)`

Reverses `Encrypt`. Calls `gcm.Open` which verifies the authentication tag before returning plaintext. Returns an error if the tag is invalid (tampered ciphertext).

---

## Security Properties

| Property | Value |
|---|---|
| Cipher | AES-256-GCM |
| Key size | 256 bits (32 bytes) |
| Nonce size | 96 bits (12 bytes), random per message |
| Authentication tag | 128 bits (16 bytes), appended to ciphertext |
| Nonce reuse | Not possible — `crypto/rand` per encrypt call |

---

## Related Files

| File | Relationship |
|---|---|
| [signer.go](./signer.md) | Signs payload before this encrypts it |
| [pkg/api/client.go](../api/client.md) | Receives encrypted payload for HTTP POST |
