# `pkg/api/tls_certificate.go` — TLS Certificate Probing

**Package:** `api`
**Path:** `pkg/api/tls_certificate.go`
**Lines:** ~117

---

## Overview

Standalone TLS certificate inspection utilities. Opens an outbound TLS connection to a `host:port`, captures the peer certificate chain without trusting it, and returns structured metadata including SHA-256 hashes of the leaf and issuer certificates. Used by `pkg/ebpf/tls_monitor.go` to populate cert fields in `TLSContext` for JA3/cert correlation.

`InsecureSkipVerify` is intentional — the purpose is to *inspect* the certificate, not to *trust* it. The hash is what matters, not chain validation.

---

## Types

### `TLSCertificateMetadata`

| Field | Type | Description |
|---|---|---|
| `Host` | string | The `host:port` that was probed |
| `LeafSubject` | string | Leaf cert Common Name or first Organisation |
| `LeafIssuer` | string | Issuer Common Name or first Organisation |
| `LeafSHA256` | string | SHA-256 hex of leaf cert DER bytes |
| `IssuerSHA256` | string | SHA-256 hex of intermediate cert DER bytes (empty if chain length 1) |
| `PublicKeySHA256` | string | SHA-256 hex of leaf's `RawSubjectPublicKeyInfo` (SPKI pin) |
| `NotBefore` | `time.Time` | Leaf cert validity start |
| `NotAfter` | `time.Time` | Leaf cert validity end |
| `SubjectAltNames` | `[]string` | Leaf cert DNS SANs |
| `ChainLength` | int | Number of peer certificates returned by server |
| `VerifiedChains` | int | Number of verified chains (0 = InsecureSkipVerify, expected) |

---

## Functions

### `ProbeTLSCertificate(ctx context.Context, hostport string, timeout time.Duration) (*TLSCertificateMetadata, error)`

Dials `hostport` over TLS, reads the peer certificate chain, and returns metadata.

**Behaviour:**
- `timeout <= 0` → defaults to 3 seconds
- Sets `ServerName` from the host portion of `hostport` — fixes SNI for multi-tenant endpoints (Bug Apr 30, 2026: without SNI, the server returns its default cert instead of the requested host's cert)
- Uses `InsecureSkipVerify: true` — inspecting, not trusting
- Returns error if no peer certificates are returned
- `IssuerSHA256` is empty when the chain has only one certificate

**Context check:** After dial, does a non-blocking `<-ctx.Done()` check. The dial itself uses a net.Dialer with `Timeout` — it does not respect context cancellation mid-dial (only post-dial).

### `CertSHA256FromX509(cert *x509.Certificate) string`

Convenience function that returns the SHA-256 hex of a certificate's raw DER bytes. Returns `""` for nil input. Used by code that already has a parsed `*x509.Certificate`.

---

## Private helpers

### `certName(n pkix.Name) string`

Returns `CommonName` if non-empty, else first `Organization`, else `""`.

### `hashBytes(b []byte) string`

SHA-256 of `b`, hex-encoded. Returns `""` for nil/empty input.

---

## Key Anchor Comment

| Lines | Anchor summary |
|---|---|
| 40–43 | `ServerName` in `ProbeTLSCertificate` — fixes wrong cert on multi-tenant TLS endpoints |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/api/client.go](./client.md) | `BuildTLSConfig` uses stdlib TLS, not this file |
| [pkg/ebpf/tls_monitor.go](../ebpf/tls_monitor.md) | Calls `probeCert()` (a local function that reimplements similar logic) for SNI cert probing |
