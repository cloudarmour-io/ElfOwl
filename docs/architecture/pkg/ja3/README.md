# `pkg/ja3/` — JA3 TLS Fingerprint Parser

**Package:** `ja3`
**Purpose:** Shared JA3/TLS ClientHello parsing library. Extracted from `pkg/ebpf` to eliminate duplication; both `pkg/ebpf` and `pkg/enrichment` import this package.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [parser.go](../../../../pkg/ja3/parser.go) | [parser.md](./parser.md) | All JA3 types and parsing functions |

---

## Why a Separate Package?

Both `pkg/ebpf` (via `ja3.go` shim) and `pkg/enrichment` need to parse TLS ClientHello bytes and compute JA3 fingerprints. Putting the implementation in either package would require the other to import it, creating a dependency cycle through `pkg/agent`. The shared `pkg/ja3` package sits below both, breaking the cycle.

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/ebpf/ja3.go](../ebpf/ja3.md) | Re-exports `ParseJA3Metadata` and `ExtractTLSClientHello` |
| [pkg/enrichment/enricher.go](../enrichment/enricher.md) | Calls `ja3.ParseJA3Metadata` in `EnrichTLSEvent` |
