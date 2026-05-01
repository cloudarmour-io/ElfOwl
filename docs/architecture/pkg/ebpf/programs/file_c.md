# `pkg/ebpf/programs/file.c` — File Access Monitor

**Path:** `pkg/ebpf/programs/file.c`
**Lines:** 557
**Output:** `bin/file.o`
**Includes:** Raw Linux headers (does NOT include `common.h`)

---

## Overview

Captures file operation events across six syscall tracepoints: `openat`, `write`, `pwrite64`, `chmod`, `fchmodat`, and `unlinkat`. Each event carries the operation type, path, flags, and process context.

---

## Why Not `common.h`?

Like `dns.c`, `file.c` predates the `common.h` refactor and uses raw Linux headers. It only reads syscall arguments (not kernel struct fields), so CO-RE is not required.

---

## Data Structures

### `file_event`

```c
struct file_event {
    u32 pid;
    u32 uid;
    u32 gid;
    char comm[16];
    char filename[256];
    u32  flags;         // O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND
    u8   operation;     // see operation constants below
    char flags_str[64]; // human-readable flags (e.g. "O_RDWR|O_CREAT")
    u32  mode;          // chmod mode bits
};
```

### Operation Constants

| Constant | Value | Syscall |
|---|---|---|
| `OP_OPEN` | `1` | `openat` |
| `OP_WRITE` | `2` | `write` |
| `OP_CHMOD` | `3` | `chmod` / `fchmodat` |
| `OP_UNLINK` | `4` | `unlinkat` |
| `OP_PWRITE` | `5` | `pwrite64` |

---

## BPF Maps

### `file_events` (perf event array)

Output perf buffer. Read by `FileMonitor` in Go.

### `file_heap` (per-CPU array, 1 entry)

Per-CPU scratch for `file_event`.

---

## Helper Functions

### `classify_open(flags) u8`

Maps `openat` flags to operation type. Returns `OP_WRITE` if `O_WRONLY` or `O_RDWR` is set and `O_CREAT` or `O_TRUNC` is set (write-intent open). Returns `OP_OPEN` otherwise. Used to distinguish read-only opens from write-intent opens in the operation field.

### `fill_common(event, ctx)`

Fills `pid`, `uid`, `gid`, `comm` fields from BPF helpers. Called at the start of every tracepoint handler.

### `set_flags_str(event)`

Builds `flags_str` by testing individual flag bits and appending their names. Produces strings like `"O_RDWR|O_CREAT|O_TRUNC"`. Uses pointer arithmetic over a fixed output buffer — no BPF string functions available.

---

## Tracepoints

### `syscalls/sys_enter_openat`

```c
SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
```

- `filename` from `ctx->args[1]` (user string pointer) via `bpf_probe_read_user_str`
- `flags` from `ctx->args[2]`
- `operation = classify_open(flags)`
- Calls `set_flags_str(event)`

### `syscalls/sys_enter_write`

```c
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
```

- `fd` from `ctx->args[0]` — stored as decimal string in `filename` field (no fd→path resolution in BPF)
- `operation = OP_WRITE`

### `syscalls/sys_enter_pwrite64`

Same structure as `write`. `operation = OP_PWRITE`. Captures positional writes.

### `syscalls/sys_enter_chmod`

```c
SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx)
```

- `filename` from `ctx->args[0]`
- `mode` from `ctx->args[1]`
- `operation = OP_CHMOD`

### `syscalls/sys_enter_fchmodat`

Same as `chmod`. `filename` from `ctx->args[1]` (after dirfd). `mode` from `ctx->args[2]`.

### `syscalls/sys_enter_unlinkat`

```c
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx)
```

- `filename` from `ctx->args[1]` (after dirfd)
- `operation = OP_UNLINK`

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](../types.md) | `FileEvent` Go struct mirrors `file_event` |
| [pkg/ebpf/file_monitor.go](../monitors.md) | Reads events, maps `operation` to `fileOperationName` |
