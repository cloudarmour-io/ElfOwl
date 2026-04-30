# `pkg/ebpf/` — eBPF Monitor Files

**Files covered:** `process_monitor.go`, `network_monitor.go`, `dns_monitor.go`, `file_monitor.go`, `capability_monitor.go`

---

## Overview

Each monitor follows an identical pattern — a thin consumer that reads raw bytes from a `ProgramSet.Reader`, decodes them into a typed kernel event struct, converts to `enrichment.EnrichedEvent`, and sends to a buffered channel. The agent reads from that channel in `handle{Xxx}Events()`.

All five monitors share the same struct layout, lifecycle methods, and concurrency model. Only the event struct, the enrichment context type populated, and a few decode helpers differ.

---

## Common Pattern

### Struct fields (identical across all monitors)

| Field | Type | Description |
|---|---|---|
| `programSet` | `*ProgramSet` | Loaded eBPF program; provides `Reader` |
| `eventChan` | `chan *enrichment.EnrichedEvent` | Buffered channel (capacity 100) to agent |
| `logger` | `*zap.Logger` | |
| `stopChan` | `chan struct{}` | Closed by `Stop()` to signal `eventLoop` |
| `wg` | `sync.WaitGroup` | Tracks the single `eventLoop` goroutine |
| `started` | `bool` | Guards double-start |
| `mu` | `sync.Mutex` | Guards `started` |

### Lifecycle methods (identical signatures)

| Method | Behaviour |
|---|---|
| `NewXxxMonitor(programSet, logger)` | Constructs monitor; does not start goroutine |
| `Start(ctx) error` | Locks `mu`, sets `started=true`, launches `eventLoop` goroutine |
| `EventChan() <-chan *enrichment.EnrichedEvent` | Returns read-only event channel |
| `Stop() error` | Locks `mu`, sets `started=false`, closes `stopChan`, `wg.Wait()`, calls `programSet.Close()` |

`Stop()` returns an error if `programSet.Close()` fails; otherwise nil.

### `eventLoop(ctx)` pattern

```
for {
    select {
    case <-ctx.Done(): return
    case <-stopChan:   return
    default:
        data = Reader.Read()        // nil, nil on timeout → sleep 10ms, continue
        error             → sleep 100ms, continue
        binary.Read(data) → decode into KernelEvent
        build enrichment.EnrichedEvent
        select {
            case eventChan <- enriched: (ok)
            case <-ctx.Done(): return
            case <-stopChan:  return
            default: warn "channel full, dropping event"
        }
    }
}
```

The outer `select` catches context and stop signals only between reads. The inner `select` on `eventChan` is non-blocking — events are dropped rather than blocking the read loop when the agent's handler falls behind.

---

## Per-Monitor Details

### `ProcessMonitor` (`process_monitor.go`)

**Kernel struct:** `ProcessEvent`
**Decode:** `binary.Read(bytes.NewReader(data), binary.LittleEndian, evt)`
**Output event type:** `"process_execution"`

Context built:
```go
enrichment.ProcessContext{
    PID:      evt.PID,
    UID:      evt.UID,
    GID:      evt.GID,
    Filename: strings.TrimRight(string(evt.Filename[:]), "\x00"),
    Command:  strings.TrimRight(string(evt.Argv[:]), "\x00"),
}
```

---

### `NetworkMonitor` (`network_monitor.go`)

**Kernel struct:** `NetworkEvent`
**Decode:** `binary.Read(bytes.NewReader(data), binary.LittleEndian, evt)`
**Output event type:** `"network_connection"`

Context built:
```go
enrichment.NetworkContext{
    SourceIP:           networkIPs(evt).src,
    DestinationIP:      networkIPs(evt).dst,
    SourcePort:         evt.SPort,
    DestinationPort:    evt.DPort,
    Protocol:           "tcp" | "udp",
    Direction:          networkDirection(evt.Direction),   // "outbound"|"inbound"|"unknown"
    ConnectionState:    tcpStateName(evt.State),
    NetworkNamespaceID: evt.NetNS,
}
```

**Helper functions:**

`networkIPs(evt)` — for `AF_INET6` reads 16-byte arrays as `net.IP`; for `AF_INET` reconstructs from 4 bytes of `SAddr`/`DAddr` (little-endian byte order).

`networkDirection(direction uint8)` — `1→"outbound"`, `2→"inbound"`, else `"unknown"`.

`tcpStateName(state uint8)` — maps 1–12 to `ESTABLISHED`, `SYN_SENT`, `SYN_RECV`, `FIN_WAIT1`, `FIN_WAIT2`, `TIME_WAIT`, `CLOSE`, `CLOSE_WAIT`, `LAST_ACK`, `LISTEN`, `CLOSING`, `NEW_SYN_RECV`.

---

### `DNSMonitor` (`dns_monitor.go`)

**Kernel struct:** `DNSEvent`
**Decode:** `binary.Read(bytes.NewReader(data), binary.LittleEndian, evt)`
**Output event type:** `"dns_query"`

Context built:
```go
enrichment.DNSContext{
    QueryName:    strings.TrimRight(string(evt.QueryName[:]), "\x00"),
    QueryType:    dnsQueryTypeName(evt.QueryType),
    ResponseCode: int(evt.ResponseCode),
    QueryAllowed: evt.QueryAllowed == 1,
}
```

**Helper functions:**

`dnsQueryTypeName(qtype uint16)` — maps RFC 1035 type numbers to strings: 1→`"A"`, 2→`"NS"`, 5→`"CNAME"`, 6→`"SOA"`, 12→`"PTR"`, 15→`"MX"`, 16→`"TXT"`, 28→`"AAAA"`, 33→`"SRV"`, 42→`"NAPTR"`, 43→`"DS"`, 48→`"DNSKEY"`, 255→`"ANY"`. Falls back to `"TYPE<n>"`.

`dnsResponseCodeName(rcode uint8)` — maps 0–10 to RFC 1035 names (`NOERROR`, `FORMERR`, `SERVFAIL`, `NXDOMAIN`, `NOTIMP`, `REFUSED`, `YXDOMAIN`, `YXRRSET`, `NXRRSET`, `NOTAUTH`, `NOTZONE`). Used only in debug logging.

`dnsServerIP(evt)` — converts `Server[16]byte` + `ServerFamily` to a printable IP string using `net.IPv4` or `net.IP`.

---

### `FileMonitor` (`file_monitor.go`)

**Kernel struct:** `FileEvent`
**Decode:** `binary.Read(bytes.NewReader(data), binary.LittleEndian, evt)`
**Output event type:** `"file_access"`

Context built:
```go
enrichment.FileContext{
    Path:      strings.TrimRight(string(evt.Filename[:]), "\x00"),
    Operation: "write"|"read"|"chmod"|"unlink"|"unknown",
    PID:       evt.PID,
    Mode:      evt.Mode,
    FD:        evt.FD,
}
```

Operation mapping: `evt.Operation` 1→`"write"`, 2→`"read"`, 3→`"chmod"`, 4→`"unlink"`, else `"unknown"`.

---

### `CapabilityMonitor` (`capability_monitor.go`)

**Kernel struct:** `CapabilityEvent`
**Decode:** `binary.Read(bytes.NewReader(data), binary.LittleEndian, evt)`
**Output event type:** `"capability_usage"`

Context built:
```go
enrichment.CapabilityContext{
    Name:      capabilityName(evt.Capability),
    Allowed:   evt.CheckType != 2,   // CheckType=2 means "use" (i.e. denied/blocked)
    PID:       evt.PID,
    SyscallID: evt.SyscallID,
}
```

`capabilityName(cap uint32)` maps 0–40 to `CAP_CHOWN` through `CAP_CHECKPOINT_RESTORE`. Falls back to `"CAP_UNKNOWN_<n>"`.

---

## TLSMonitor — separate doc

`TLSMonitor` follows the same pattern but has additional complexity (cert probing, JA3 parsing, SNI cache). See [tls_monitor.md](./tls_monitor.md).

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](./types.md) | Kernel event struct definitions decoded here |
| [pkg/ebpf/loader.go](./loader.md) | Provides `ProgramSet` consumed by each monitor |
| [pkg/enrichment/types.go](../enrichment/types.md) | `EnrichedEvent`, all `*Context` types produced here |
| [pkg/agent/agent.go](../agent/agent.md) | Constructs monitors, reads from `EventChan()` |
