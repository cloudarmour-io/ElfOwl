# `pkg/ebpf/tls_monitor.go` — TLS ClientHello Monitor

**Package:** `ebpf`
**Path:** `pkg/ebpf/tls_monitor.go`
**Lines:** ~251
**Added:** (integrated with other monitors) / cert cache: Apr 26, 2026

---

## Overview

Extends the standard monitor pattern with two extra capabilities:

1. **JA3 fingerprinting** — parses the raw TLS ClientHello bytes captured by the eBPF program and computes JA3/JA3S fingerprints in userspace via `ParseJA3Metadata()`
2. **Certificate probing with SNI cache** — dials the destination host asynchronously to fetch the actual server certificate, then caches it by SNI with a 10-minute TTL

The TLS event struct cannot use `binary.Read` due to C packed-struct layout; all decoding goes through `DecodeTLSEvent()`.

---

## Types

### `certCacheEntry`

| Field | Type | Description |
|---|---|---|
| `sha256` | string | Colon-separated SHA-256 of leaf cert DER |
| `issuer` | string | Leaf cert issuer Common Name |
| `expiry` | `int64` | Leaf cert `NotAfter` as Unix timestamp |
| `fetchedAt` | `time.Time` | When the entry was populated (for TTL check) |

`certCacheTTL = 10 * time.Minute` — matches default vaanvil cache TTL.

### `TLSMonitor`

| Field | Type | Description |
|---|---|---|
| `programSet` | `*ProgramSet` | |
| `eventChan` | `chan *enrichment.EnrichedEvent` | Capacity 100 |
| `logger` | `*zap.Logger` | |
| `stopChan` | `chan struct{}` | |
| `wg` | `sync.WaitGroup` | Tracks `eventLoop` goroutine |
| `started` | `bool` | Guards double-start |
| `mu` | `sync.Mutex` | Guards `started` |
| `certCache` | `map[string]*certCacheEntry` | SNI → cert metadata |
| `certCacheMu` | `sync.Mutex` | Guards `certCache` |

---

## Functions

### `NewTLSMonitor(programSet, logger) *TLSMonitor`

Constructs monitor with an empty `certCache` map.

### `Start(ctx) error` / `Stop() error` / `EventChan()`

Same pattern as other monitors. `Stop()` closes `stopChan`, waits for `wg`, then calls `programSet.Close()`.

### `getCachedCert(sni string) *certCacheEntry`

Locks `certCacheMu`, looks up `sni`. Returns `nil` if absent or if `time.Since(e.fetchedAt) > certCacheTTL`.

### `setCachedCert(sni string, e *certCacheEntry)`

Locks `certCacheMu`, stores entry. Called from the background cert probe goroutine.

### `eventLoop(ctx context.Context)`

**Full processing path per event:**

1. `Reader.Read()` — raw bytes
2. `DecodeTLSEvent(data)` — manual packed-struct decode (see `types.go`)
3. Build skeleton `EnrichedEvent{EventType: "tls_client_hello", TLS: &TLSContext{}}`
4. `ParseJA3Metadata(evt.Metadata[:evt.Length])` — parse ClientHello, compute JA3 fingerprint
   - On parse error: log `Warn "tls ja3 parse failed, event dropped"` and skip TLS context population (event still forwarded with empty TLS context)
5. On success: populate `TLSContext` with JA3 fields
6. **Cert probe (SNI non-empty):**
   - Cache hit → populate `CertSHA256`, `CertIssuer`, `CertExpiry` immediately
   - Cache miss → launch background goroutine calling `probeCert(sni, dstPort)`; event ships with empty cert fields; subsequent events for same SNI get cached values
7. Non-blocking send to `eventChan`

**Cache miss trade-off:** Event #1 to a new SNI ships without cert data. All events within the 10-minute TTL window get cert data. Reliable event capture was prioritised over complete cert data on the first event.

### `probeCert(sni string, port uint16) (certSHA256, issuer string, expiry int64)`

Dials `sni:port` using `tls.DialWithDialer` with a 3-second timeout and `InsecureSkipVerify`. Returns cert metadata or empty strings on failure.

**SHA-256 format:** colon-separated hex pairs matching vaanvil format: `"ab:cd:ef:..."` (32 pairs).

**Port parameter fix (Apr 30, 2026):** Previously hardcoded port 443. Services on non-standard TLS ports (6443, 8443, 5671) never got cert metadata. Now uses `evt.DstPort` from the captured event.

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 18–24 | `certCacheEntry` — per-SNI cert cache with 10-min TTL |
| 38–41 | `certCache` field on `TLSMonitor` |
| 129–132 | TLS version drop log — out-of-range `legacy_version` events logged at Warn |
| 159–165 | Cert probe strategy — async miss, immediate cache hit |
| 209–210 | `probeCert` port parameter — non-standard TLS port fix |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](./types.md) | `TLSClientHelloEvent`, `DecodeTLSEvent` |
| [pkg/ebpf/ja3.go](./ja3.md) | `ParseJA3Metadata` re-exported from `pkg/ja3` |
| [pkg/api/tls_certificate.go](../api/tls_certificate.md) | Similar cert probing utility (for the OWL API client) |
| [pkg/agent/agent.go](../agent/agent.md) | `handleTLSEvent` wraps enricher to preserve cert fields after enrichment |
