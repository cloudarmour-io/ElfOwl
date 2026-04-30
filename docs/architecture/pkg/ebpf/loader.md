# `pkg/ebpf/loader.go` — eBPF Program Loader

**Package:** `ebpf`
**Path:** `pkg/ebpf/loader.go`
**Lines:** ~1129 (combined with types.go in source)
**Added:** Dec 27, 2025

---

## Overview

Implements all eBPF program lifecycle management using the `github.com/cilium/ebpf` library. Responsible for:

1. Extracting embedded ELF bytecode via `bytecode_embed.go`
2. Parsing ELF specs and loading programs into the kernel
3. Attaching programs to tracepoints or raw tracepoints
4. Creating event readers (perf buffer or ring buffer)
5. Managing clean shutdown (detach links, close maps and programs)

Also defines the `Reader` interface and its two implementations (`PerfBufferReader`, `RingBufferReader`), and all loader configuration types used by `agent.go`.

---

## Interfaces

### `Reader`

```go
type Reader interface {
    Read() ([]byte, error)   // returns next raw event bytes, or nil on timeout
    Close() error
}
```

Implemented by `PerfBufferReader` and `RingBufferReader`. Monitors call `Read()` in a tight loop; a `nil, nil` return means timeout/no data (not an error).

---

## Configuration Types

### `ProgramConfig`

| Field | Description |
|---|---|
| `Enabled` | Load and attach this program |
| `BufferSize` | Perf buffer size hint (bytes); overrides `PerfBufferOptions.PageCount` when > 0 |
| `Timeout` | `Read()` deadline; `0` = block indefinitely |

### `PerfBufferOptions`

| Field | Default | Description |
|---|---|---|
| `Enabled` | true | Use perf buffers (all kernel versions) |
| `PageCount` | 64 | Per-CPU pages for the perf ring |
| `LostHandler` | true | Log a warning when `LostSamples > 0` |

### `RingBufferOptions`

| Field | Default | Description |
|---|---|---|
| `Enabled` | false | Use ring buffer (kernel 5.8+) — preferred for modern kernels |
| `Size` | 65536 | Ring buffer size in bytes |

### `LoadOptions`

Top-level options struct passed to `LoadProgramsWithOptions`. Contains one `ProgramConfig` per monitor type plus `PerfBufferOptions`, `RingBufferOptions`, and `KernelBTFPath`.

---

## Struct Types

### `ProgramSet`

Wraps a loaded, kernel-attached eBPF program and its resources.

| Field | Type | Description |
|---|---|---|
| `Program` | `*ebpf.Program` | Primary loaded program |
| `Programs` | `map[string]*ebpf.Program` | All programs from collection (for multi-tracepoint modules) |
| `Maps` | `map[string]*ebpf.Map` | All maps including perf/ringbuf event map |
| `Reader` | `Reader` | Event stream reader (perf or ring buffer) |
| `Links` | `[]link.Link` | Attached kernel links — closed on shutdown |
| `Logger` | `*zap.Logger` | |

### `Collection`

Top-level container for all six loaded `ProgramSet` instances.

| Field | Type |
|---|---|
| `Process` | `*ProgramSet` |
| `Network` | `*ProgramSet` |
| `File` | `*ProgramSet` |
| `Capability` | `*ProgramSet` |
| `DNS` | `*ProgramSet` |
| `TLS` | `*ProgramSet` |
| `Logger` | `*zap.Logger` |

---

## Functions

### `DefaultLoadOptions() LoadOptions`

All six programs enabled, perf buffer enabled (64 pages, lost handler), ring buffer disabled.

### `LoadPrograms(logger) (*Collection, error)`

Calls `LoadProgramsWithOptions` with `DefaultLoadOptions()`.

### `LoadProgramsWithOptions(logger, opts) (*Collection, error)`

Main entry point called by `agent.Start()`.

**For each enabled program:**
1. `loadProgramSet(logger, def, opts)` — loads, attaches, creates reader
2. Assigns the resulting `*ProgramSet` to the corresponding `Collection` field

Returns a complete `Collection` or an error on first failure.

### `loadProgramSet(logger, def, opts) (*ProgramSet, error)`

Loads a single program set.

**Steps:**
1. `GetProgram(def.Name)` — fetch embedded `.o` bytecode
2. Validate ELF magic (`0x7f 'E' 'L' 'F'`) and minimum size (64 bytes)
3. `ebpf.LoadCollectionSpecFromReader()` — parse ELF
4. Load optional kernel BTF spec from `opts.KernelBTFPath` (CO-RE portability)
5. `ebpf.NewCollectionWithOptions()` — load into kernel
6. `attachPrograms()` — attach all tracepoint sections found in the collection
7. `selectEventMap()` — find the perf/ringbuf map by preferred name
8. `createReader()` — build `PerfBufferReader` or `RingBufferReader`
9. Return `ProgramSet` with all resources tracked

### `attachPrograms(logger, setName, programs, sections) (links, attached, infos, error)`

Iterates all programs in the loaded collection. For each:
- Parses section name via `parseTracepointSection()` to determine kind (`tracepoint` / `raw_tracepoint`), group, and name
- Attaches via `link.Tracepoint()` or `link.AttachRawTracepoint()`
- On `isMissingTracepointError`: logs a warning and skips (graceful degradation on kernels without a specific tracepoint)
- On other errors: closes all already-opened links and returns the error

Returns the slice of `link.Link` handles and the map of attached programs.

### `parseTracepointSection(section string) (kind, group, name string, ok bool)`

Parses ELF section names:
- `"tracepoint/syscalls/sys_enter_execve"` → `("tracepoint", "syscalls", "sys_enter_execve", true)`
- `"raw_tracepoint/tcp_connect"` → `("raw_tracepoint", "", "tcp_connect", true)`
- Anything else → `("", "", "", false)` (program is skipped)

### `selectEventMap(maps, preferred) (name, *ebpf.Map)`

Returns the map named `preferred` if present; otherwise falls back to the first map of type `PerfEventArray` or `RingBuf`.

### `createReader(eventMap, def, opts, logger) (Reader, error)`

Dispatches on `eventMap.Type()`:
- `ebpf.RingBuf` → `RingBufferReader` (requires `opts.RingBuffer.Enabled`)
- `ebpf.PerfEventArray` → `PerfBufferReader` (requires `opts.PerfBuffer.Enabled`)
- Other types → error

### `selectTracepointProgram(programs) (string, *ebpf.Program)`

Preference order: `ebpf.TracePoint` → `ebpf.RawTracepoint` → any. Used when multi-attach is not needed.

### `attachProgram(def, prog) (link.Link, error)`

Single-program attach used as a fallback. Dispatches on `prog.Type()`.

### `isMissingTracepointError(err error) bool`

Returns true for `os.ErrNotExist` or error messages containing `"enoent"` or `"no such file or directory"` near `"/events/"` or `"tracepoint"`. Allows graceful degradation on kernels that don't expose a particular tracepoint.

### `perfBufferSize(def, opts) int`

Priority: `def.Config.BufferSize > 0` → use it; else `opts.PerfBuffer.PageCount * os.Getpagesize()`; else `64 * os.Getpagesize()`.

### `closeLinks(links []link.Link)`

Closes all non-nil links, ignoring errors. Used for cleanup on partial attach failures.

---

## `Collection.Close() error`

Closes all non-nil `ProgramSet` instances in order. Collects errors and returns them joined.

## `ProgramSet.Close() error`

Shutdown order:
1. `Reader.Close()` — unblocks any in-progress `Read()`
2. Close all `Links` — detaches tracepoints from kernel
3. Close all `Maps` — de-duplicates by pointer to avoid double-close
4. Close all `Programs` — de-duplicates by pointer

---

## Reader Implementations

### `PerfBufferReader`

Wraps `perf.Reader` from `github.com/cilium/ebpf/perf`.

- `Read()`: sets deadline if `timeout > 0`; returns `nil, nil` on deadline exceeded (not an error); copies `RawSample` to avoid re-use after return; logs dropped samples if `lostHandler=true` and `LostSamples > 0`
- `Close()`: ignores `os.ErrClosed` on `reader.Close()` (idempotent close)

### `RingBufferReader`

Wraps `ringbuf.Reader` from `github.com/cilium/ebpf/ringbuf`.

- Same `Read()` / `Close()` pattern as `PerfBufferReader` minus the lost-sample logging
- Preferred over perf buffer on kernel 5.8+ (single shared buffer, lower overhead)

---

## Tracepoint Assignments

| Program | Attach type | Group | Name |
|---|---|---|---|
| process | tracepoint | `syscalls` | `sys_enter_execve` |
| network | tracepoint | `tcp` | `tcp_connect` |
| file | tracepoint | `syscalls` | `sys_enter_openat` |
| capability | tracepoint | `capability` | `cap_capable` |
| dns | tracepoint | `syscalls` | `sys_enter_sendto` |
| tls | tracepoint | `syscalls` | `sys_enter_write` |

---

## Key Anchor Comments

| Lines | Anchor summary |
|---|---|
| 298–300 | `ProgramSet.Programs` — multi-program support for multi-tracepoint modules |
| 309–311 | `ProgramSet.Links` — track links for clean detach on shutdown |
| 459–462 | `loadProgramSet` — single program load + tracepoint attach |
| 480–482 | Kernel BTF override — CO-RE portability for custom BTF vmlinux |
| 508–510 | Multi-tracepoint attach — attach every section found |
| 569–571 | Multi-tracepoint attach helpers |
| 701–703 | `selectTracepointProgram` — prefers `TracePoint` over fallbacks |
| 740–742 | `selectEventMap` — perf/ringbuf map lookup |
| 757–759 | `createReader` — perf/ringbuf reader wiring |
| 936–938 | `ProgramSet.Close` — detach links before closing programs |
| 947–949 | Close all maps once — de-duplicate by pointer |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](./types.md) | Event struct definitions decoded by monitors |
| [pkg/ebpf/bytecode_embed.go](./bytecode_embed.md) | `GetProgram()` — provides embedded ELF bytecode |
| [pkg/ebpf/process_monitor.go](./process_monitor.md) | Consumes `*ProgramSet` from `Collection.Process` |
| [pkg/agent/agent.go](../agent/agent.md) | Calls `LoadProgramsWithOptions`, creates monitors from returned `Collection` |
