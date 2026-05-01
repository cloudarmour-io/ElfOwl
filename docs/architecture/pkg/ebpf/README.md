# `pkg/ebpf/` — eBPF Monitor Package

**Package:** `ebpf`
**Purpose:** Loads compiled eBPF programs into the kernel, attaches them to tracepoints, and streams decoded kernel events to the enrichment pipeline via typed channels.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [types.go](../../../../pkg/ebpf/types.go) | [types.md](./types.md) | Kernel event structs, constants, `DecodeTLSEvent` |
| [loader.go](../../../../pkg/ebpf/loader.go) | [loader.md](./loader.md) | ELF loading, tracepoint attach, `ProgramSet`, `Collection`, reader types |
| [bytecode_embed.go](../../../../pkg/ebpf/bytecode_embed.go) | [bytecode_embed.md](./bytecode_embed.md) | `//go:embed` for compiled `.o` files; `GetProgram()` |
| [process_monitor.go](../../../../pkg/ebpf/process_monitor.go) | [monitors.md](./monitors.md) | Process execution events |
| [network_monitor.go](../../../../pkg/ebpf/network_monitor.go) | [monitors.md](./monitors.md) | Network connection events |
| [dns_monitor.go](../../../../pkg/ebpf/dns_monitor.go) | [monitors.md](./monitors.md) | DNS query events |
| [file_monitor.go](../../../../pkg/ebpf/file_monitor.go) | [monitors.md](./monitors.md) | File access events |
| [capability_monitor.go](../../../../pkg/ebpf/capability_monitor.go) | [monitors.md](./monitors.md) | Linux capability usage events |
| [tls_monitor.go](../../../../pkg/ebpf/tls_monitor.go) | [tls_monitor.md](./tls_monitor.md) | TLS ClientHello — JA3 parsing + cert probing |
| [ja3.go](../../../../pkg/ebpf/ja3.go) | [ja3.md](./ja3.md) | JA3 shim re-exporting `pkg/ja3` |

### Test files (not separately documented)

| File | What it tests |
|---|---|
| `bytecode_embed_test.go` | `GetProgram`, `ListPrograms` |
| `process_monitor_test.go` | Monitor start/stop/event flow |
| `network_monitor_test.go` | IP parsing, direction/state helpers |
| `dns_monitor_test.go` | Query type / rcode helpers |
| `file_monitor_test.go` | Operation mapping |
| `capability_monitor_test.go` | Capability name mapping |
| `ja3_test.go` | JA3 parsing correctness |
| `monitor_test_helpers.go` | Shared fake `ProgramSet` for tests |
| `lifecycle_test.go` | Start/stop idempotency |
| `integration_test.go` | Full pipeline integration |
| `loader_integration_test.go` | Loader with fake bytecode |
| `pipeline_integration_test.go` | Monitor → enrichment pipeline |

---

## Architecture

```
programs/bin/*.o   (compiled by make)
        │
        ▼
bytecode_embed.go  GetProgram()
        │
        ▼
loader.go          LoadProgramsWithOptions()
        │           → loadProgramSet()
        │               → ELF parse → kernel load → tracepoint attach
        │               → createReader() → PerfBufferReader | RingBufferReader
        │
        ▼
Collection { Process, Network, File, Capability, DNS, TLS *ProgramSet }
        │
        ▼
XxxMonitor.Start()   (one goroutine per monitor)
        │   eventLoop: Read() → decode → build EnrichedEvent
        ▼
chan *enrichment.EnrichedEvent   →   agent.handle{Xxx}Events()
```

---

## Tracepoints

| Monitor | Tracepoint |
|---|---|
| process | `syscalls/sys_enter_execve` |
| network | `tcp/tcp_connect` |
| file | `syscalls/sys_enter_openat` |
| capability | `capability/cap_capable` |
| dns | `syscalls/sys_enter_sendto` |
| tls | `syscalls/sys_enter_write` |

---

## Key Design Notes

- All five simple monitors (`Process`–`Capability`) share an identical struct layout and lifecycle — only the kernel struct and context type differ. See [monitors.md](./monitors.md).
- `TLSMonitor` adds cert probing and JA3 parsing. See [tls_monitor.md](./tls_monitor.md).
- `TLSClientHelloEvent` cannot be decoded with `binary.Read` due to C packed-struct alignment differences. See `DecodeTLSEvent` in [types.md](./types.md).
- Events are dropped (not backpressured) when the agent's handler channel is full.

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/enrichment/](../../../../pkg/enrichment/) | `EnrichedEvent` and all `*Context` types produced by monitors |
| [pkg/agent/](../../../../pkg/agent/) | Constructs monitors from `Collection`, reads event channels |
| `pkg/ja3/` | JA3 fingerprint computation (re-exported via `ja3.go`) |
| `github.com/cilium/ebpf` | Core eBPF library used by `loader.go` |
