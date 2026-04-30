# `pkg/ebpf/types.go` — eBPF Shared Types and Constants

**Package:** `ebpf`
**Path:** `pkg/ebpf/types.go`
**Lines:** ~251
**Added:** Dec 27, 2025

---

## Overview

Defines every Go type and constant that mirrors a kernel-side eBPF struct or enum. These types are the boundary between the kernel BPF programs and Go userspace — each struct layout must exactly match the corresponding C struct in `pkg/ebpf/programs/`.

Also contains `DecodeTLSEvent`, the manual packed-struct decoder needed because the TLS event struct uses `__attribute__((packed))` in C, which produces a layout that Go's default struct alignment would not reproduce.

---

## Program and Map Name Constants

```go
// Program names (match .o filenames in programs/bin/)
ProcessProgramName    = "process"
NetworkProgramName    = "network"
FileProgramName       = "file"
CapabilityProgramName = "capability"
DNSProgramName        = "dns"
TLSProgramName        = "tls"

// Perf/ringbuf map names (must match BPF_PERF_OUTPUT names in C)
ProcessEventsMap    = "process_events"
NetworkEventsMap    = "network_events"
FileEventsMap       = "file_events"
CapabilityEventsMap = "capability_events"
DNSEventsMap        = "dns_events"
TLSEventsMap        = "tls_events"
```

---

## Kernel Event Structs

All structs use fixed-size arrays for strings to match the C layout exactly. Monitors decode kernel bytes into these structs via `binary.Read(bytes.NewReader(data), binary.LittleEndian, evt)`.

### `ProcessEvent`

Matches `struct process_event` in `programs/process.c`.

| Field | Type | Description |
|---|---|---|
| `PID` | `uint32` | Process ID |
| `UID` | `uint32` | User ID |
| `GID` | `uint32` | Group ID |
| `Capabilities` | `uint64` | Capability bitmask |
| `Filename` | `[256]byte` | Executable path (null-terminated) |
| `Argv` | `[256]byte` | Command line arguments (null-terminated) |
| `CgroupID` | `uint64` | cgroup v2 ID for container identification |

### `NetworkEvent`

Matches `struct network_event` in `programs/network.c`. Extended Mar 25, 2026 to add IPv6 and connection state.

| Field | Type | Description |
|---|---|---|
| `PID` | `uint32` | |
| `Family` | `uint16` | `AF_INET=2` or `AF_INET6=10` |
| `SPort` | `uint16` | Source port (host byte order) |
| `DPort` | `uint16` | Destination port (host byte order) |
| `SAddr` | `uint32` | IPv4 source address |
| `DAddr` | `uint32` | IPv4 destination address |
| `SAddrV6` | `[16]byte` | IPv6 source address |
| `DAddrV6` | `[16]byte` | IPv6 destination address |
| `Protocol` | `uint8` | `IPPROTO_TCP=6`, `IPPROTO_UDP=17` |
| `Direction` | `uint8` | `1=outbound`, `2=inbound` |
| `State` | `uint8` | TCP state integer (1=ESTABLISHED … 12=NEW_SYN_RECV) |
| `NetNS` | `uint32` | Network namespace ID |
| `CgroupID` | `uint64` | |

### `FileEvent`

Matches `struct file_event` in `programs/file.c`. Extended Mar 25, 2026 to add `Mode` and `FD`.

| Field | Type | Description |
|---|---|---|
| `PID` | `uint32` | |
| `Flags` | `uint32` | Open/operation flags (O_WRONLY, O_RDWR, etc.) |
| `Mode` | `uint32` | chmod/openat mode bits |
| `FD` | `uint32` | File descriptor (write/pwrite fd, or *at dir fd) |
| `Operation` | `uint8` | `1=write`, `2=read`, `3=chmod`, `4=unlink` |
| `CgroupID` | `uint64` | |
| `Filename` | `[256]byte` | File path (null-terminated) |
| `FlagsStr` | `[32]byte` | Human-readable flags string |

### `CapabilityEvent`

Matches `struct capability_event` in `programs/capability.c`. Extended Mar 25, 2026 to add `SyscallID`.

| Field | Type | Description |
|---|---|---|
| `PID` | `uint32` | |
| `Capability` | `uint32` | Linux capability number (0–40) |
| `CheckType` | `uint8` | `1=check`, `2=use` |
| `SyscallID` | `uint32` | Syscall that triggered the capability check |
| `CgroupID` | `uint64` | |
| `SyscallName` | `[32]byte` | Syscall name string |

### `DNSEvent`

Matches `struct dns_event` in `programs/dns.c`. Extended Mar 25, 2026 to add IPv6 server visibility.

| Field | Type | Description |
|---|---|---|
| `PID` | `uint32` | |
| `QueryType` | `uint16` | RFC 1035 type (A=1, AAAA=28, MX=15, etc.) |
| `ResponseCode` | `uint8` | RFC 1035 rcode (0=NOERROR, 3=NXDOMAIN, etc.) |
| `QueryAllowed` | `uint8` | `1=allowed`, `0=suspicious/blocked` |
| `ServerFamily` | `uint16` | `AF_INET=2` or `AF_INET6=10` |
| `CgroupID` | `uint64` | |
| `QueryName` | `[256]byte` | Domain name (null-terminated) |
| `Server` | `[16]byte` | DNS server IP (4 or 16 bytes depending on family) |

### `TLSClientHelloEvent`

Captures the first bytes of an outbound TLS ClientHello. **Cannot be decoded with `binary.Read`** — see `DecodeTLSEvent`.

| Field | Packed offset | Type | Description |
|---|---|---|---|
| `PID` | 0 | `uint32` | |
| `Family` | 4 | `uint16` | |
| `Protocol` | 6 | `uint8` | |
| `Direction` | 7 | `uint8` | |
| `SrcPort` | 8 | `uint16` | |
| `DstPort` | 10 | `uint16` | |
| `CgroupID` | 12 | `uint64` | |
| `Length` | 20 | `uint32` | Actual bytes captured in `Metadata` |
| `Metadata` | 24 | `[2048]byte` | Raw ClientHello bytes |

**Why 2048 bytes:** TLS 1.3 with PQ-hybrid `key_share` extensions (X25519Kyber768) reaches ~1200 bytes. The previous 1024-byte limit produced truncated and inconsistent JA3 fingerprints (Bug Apr 29, 2026).

---

## `DecodeTLSEvent(b []byte) (*TLSClientHelloEvent, error)`

Manual decoder that reads at explicit little-endian offsets rather than using `binary.Read`. Required because the C struct uses `__attribute__((packed))` which eliminates alignment padding, but Go inserts 4 bytes of padding before `CgroupID` (aligning uint64 to offset 16 instead of 12). Without this function, `CgroupID`, `Length`, and `Metadata` would all read from wrong offsets.

Minimum input size: `tlsEventFixedSize = 24` bytes (the fixed fields before `Metadata`).

---

## Capability Number Constants

From `include/uapi/linux/capability.h`:

| Constant | Value |
|---|---|
| `CapSysAdmin` | 21 |
| `CapSysModule` | 16 |
| `CapSysBoot` | 22 |
| `CapSysPtrace` | 19 |
| `CapNetAdmin` | 12 |
| `CapSysRawio` | 17 |
| `CapSysResource` | 24 |

---

## File Operation Constants

| Constant | Value | Meaning |
|---|---|---|
| `FileOpWrite` | 1 | `write` / `pwrite` |
| `FileOpRead` | 2 | `read` / `pread` |
| `FileOpChmod` | 3 | `chmod` |
| `FileOpUnlink` | 4 | `unlink` |

---

## Network Constants

| Constant | Value |
|---|---|
| `AF_INET` | 2 |
| `AF_INET6` | 10 |
| `AF_UNSPEC` | 0 |
| `IPPROTO_TCP` | 6 |
| `IPPROTO_UDP` | 17 |

## DNS Constants

Query types (RFC 1035): `DNSTypeA=1`, `DNSTypeAAAA=28`, `DNSTypeMX=15`, `DNSTypeTXT=16`, `DNSTypeCNAME=5`, `DNSTypeSOA=6`, `DNSTypeNS=2`, `DNSTypeANY=255`

Response codes (RFC 1035): `DNSRCodeNoError=0`, `DNSRCodeFormErr=1`, `DNSRCodeServFail=2`, `DNSRCodeNameErr=3`, `DNSRCodeNotImpl=4`, `DNSRCodeRefused=5`

## File Open Flag Constants

From `include/uapi/asm-generic/fcntl.h`: `O_WRONLY=1`, `O_RDWR=2`, `O_CREAT=64`, `O_EXCL=128`, `O_TRUNC=512`, `O_APPEND=1024`, `O_NONBLOCK=2048`

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 56–57 | `NetworkEvent` extended layout — IPv6 + state metadata (Mar 25, 2026) |
| 78–79 | `FileEvent` mode + fd fields — expanded file syscall coverage |
| 95–96 | `CapabilityEvent` syscall id — syscall attribution |
| 110–111 | `DNSEvent` server family — IPv6 DNS visibility |
| 136–139 | TLS buffer size 2048 — PQ-hybrid key_share extension support |
| 144–148 | `DecodeTLSEvent` packed decode — why manual offset reads are required |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/loader.go](./loader.md) | Uses these structs via `ProgramSet`; defines `ProgramSet`, `Collection`, reader types |
| [pkg/ebpf/tls_monitor.go](./tls_monitor.md) | Calls `DecodeTLSEvent` |
| `pkg/ebpf/programs/*.c` | Kernel-side C structs that these Go types must mirror |
