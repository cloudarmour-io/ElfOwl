# `pkg/ebpf/ja3.go` — JA3 Re-exports

**Package:** `ebpf`
**Path:** `pkg/ebpf/ja3.go`
**Lines:** ~15
**Added:** Apr 29, 2026 (refactor)

---

## Overview

Thin re-export shim. The actual JA3 implementation lives in `pkg/ja3`. This file keeps the `pkg/ebpf` API surface stable — `tls_monitor.go` calls `ParseJA3Metadata` and `ExtractTLSClientHello` without needing an import path change.

---

## Exports

### `type JA3Metadata = ja3.JA3Metadata`

Type alias (not a new type) so callers can use `ebpf.JA3Metadata` and `ja3.JA3Metadata` interchangeably.

### `func ParseJA3Metadata(clientHello []byte) (*JA3Metadata, error)`

Delegates to `ja3.ParseJA3Metadata`. Parses a raw TLS ClientHello byte slice and returns:
- `JA3Fingerprint` — MD5 of the JA3 string
- `JA3String` — `<TLSVersion>,<CipherSuites>,<Extensions>,<EllipticCurves>,<EllipticCurvePointFormats>`
- `TLSVersion`, `SNI`, `Ciphers`, `Extensions`, `Curves`, `PointFormats`

### `func ExtractTLSClientHello(b []byte) (string, []uint16, []uint16, []uint16, []uint8, error)`

Delegates to `ja3.ExtractTLSClientHello`. Returns raw parsed components (SNI string, cipher suites, extensions, curves, point formats).

---

## Key Anchor Comment

| Lines | Anchor summary |
|---|---|
| 251–253 | JA3 re-exports — refactor to eliminate duplication between `pkg/ebpf` and `pkg/enrichment` |

---

## Related Files

| File | Relationship |
|---|---|
| `pkg/ja3/` | Real implementation |
| [pkg/ebpf/tls_monitor.go](./tls_monitor.md) | Calls `ParseJA3Metadata` via this shim |
