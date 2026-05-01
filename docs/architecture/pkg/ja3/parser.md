# `pkg/ja3/parser.go` — JA3 Parser

**Package:** `ja3`
**Path:** `pkg/ja3/parser.go`
**Lines:** 303
**Added:** Apr 29, 2026 (refactor — extracted from `pkg/ebpf/ja3.go`)

---

## Overview

Full JA3 TLS fingerprint implementation. Parses a raw TLS ClientHello byte slice, extracts the five JA3 components, filters GREASE values, and computes the MD5 fingerprint.

Accepts either a full TLS record (starting `0x16`) or a bare handshake body (starting `0x01`). `NormalizeClientHello` handles the distinction.

---

## Types

### `JA3Metadata`

```go
type JA3Metadata struct {
    TLSVersion     string
    Ciphers        []uint16
    Extensions     []uint16
    Curves         []uint16
    PointFormats   []uint8
    JA3String      string    // "<ver>,<ciphers>,<exts>,<curves>,<pf>"
    JA3Fingerprint string    // MD5 hex of JA3String
    SNI            string    // from server_name extension (0x0000)
}
```

---

## Functions

### `ParseJA3Metadata(clientHello []byte) (*JA3Metadata, error)`

Top-level entry point. Calls `NormalizeClientHello` → `ExtractTLSClientHello` → `BuildJA3String` → MD5 → `ExtractSNI`. Returns a fully populated `*JA3Metadata`.

### `NormalizeClientHello(b []byte) ([]byte, error)`

Strips the 5-byte TLS record header (`0x16 0x03xx length`) if present, leaving the raw handshake body starting at the `0x01` ClientHello byte. Passes bare handshake bodies through unchanged. Returns an error if the record type is not Handshake or the message type is not ClientHello.

### `ExtractTLSClientHello(body []byte) (tlsVersion, ciphers, extensions, curves, pointFormats, error)`

Parses the ClientHello handshake body field by field:

| Step | Offset | Field |
|---|---|---|
| 1 | 0 | Handshake type — must be `0x01` |
| 2 | 4–5 | `legacy_version` — validated `0x0301`–`0x0304` |
| 3 | 6–37 | 32-byte random — skipped |
| 4 | 38 | Session ID length + data — skipped |
| 5 | +2 | Cipher suite list — parsed, GREASE filtered |
| 6 | +1 | Compression methods — skipped |
| 7 | +2 | Extensions total length |
| 8 | loop | Per-extension: type + size + data |

**GREASE filtering** (`IsGREASEValue`): values matching `v & 0x0f0f == 0x0a0a && high_byte == low_byte` (RFC 8701) are silently skipped in cipher suites, extensions, and curves.

**Graceful truncation** — both cipher and extension length fields are clamped to available bytes rather than returning an error. Partial captures from the 2048-byte eBPF buffer still yield usable fingerprints.

Extension handlers:

| Type | Name | Extracts |
|---|---|---|
| `0x000a` | `supported_groups` | `curves []uint16` |
| `0x000b` | `ec_point_formats` | `pointFormats []uint8` |
| all others | — | appended to `extensions []uint16` |

### `ExtractSNI(body []byte) string`

Walks the extensions block of a normalised ClientHello body to find extension type `0x0000` (`server_name`). Returns the first hostname entry. Returns `""` if absent or body is too short.

### `BuildJA3String(version, ciphers, extensions, curves, pointFormats) string`

Formats the five JA3 components as a comma-separated string with dash-joined numeric lists:

```
<TLSVersion>,<Ciphers-dash-joined>,<Extensions-dash-joined>,<Curves-dash-joined>,<PointFormats-dash-joined>
```

Empty lists produce an empty field (two adjacent commas).

### `IsGREASEValue(v uint16) bool`

Returns true if `v` is a TLS GREASE value per RFC 8701 — any value where both bytes are equal and end in `0x0a` (e.g. `0x0a0a`, `0x1a1a`, ..., `0xfafa`).

### `JoinUint16s(v []uint16) string` / `JoinUint8s(v []uint8) string`

Format numeric slices as dash-separated decimal strings. Return `""` for empty slices.

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 83–88 | TLS version sanity check — rejects non-ClientHello records parsed as ClientHello |
| 112–116 | Graceful cipher truncation — partial eBPF captures still yield cipher lists |
| 144–148 | Graceful extension truncation — matches vaanvil behaviour |
| 197–199 | SNI extraction from `server_name` extension (0x0000) |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/ja3.go](../ebpf/ja3.md) | Re-exports `ParseJA3Metadata`, `ExtractTLSClientHello` from this package |
| [pkg/enrichment/enricher.go](../enrichment/enricher.md) | Calls `ja3.ParseJA3Metadata` in `EnrichTLSEvent` |
| [pkg/ebpf/tls_monitor.go](../ebpf/tls_monitor.md) | Calls `ParseJA3Metadata` via the `pkg/ebpf` shim |
