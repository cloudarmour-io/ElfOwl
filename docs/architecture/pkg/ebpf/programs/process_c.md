# `pkg/ebpf/programs/process.c` — Process Execution Monitor

**Path:** `pkg/ebpf/programs/process.c`
**Lines:** 79
**Output:** `bin/process.o`
**Includes:** `common.h`

---

## Overview

Captures process execution events by attaching to `execve` and `execveat` syscall tracepoints. Emits one `process_event` per exec attempt (both entry; no exit tracepoint).

---

## Data Structures

### `process_event`

```c
struct process_event {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u64 cap_effective;
    u32 netns;
    char comm[16];
    char filename[256];
};
```

| Field | Source | Description |
|---|---|---|
| `pid` | `bpf_get_current_pid_tgid() >> 32` | Process ID (TGID) |
| `ppid` | `BPF_CORE_READ(task, real_parent, tgid)` | Parent process ID |
| `uid` | `bpf_get_current_uid_gid() & 0xFFFFFFFF` | Effective UID |
| `gid` | `bpf_get_current_uid_gid() >> 32` | Effective GID |
| `cap_effective` | `current_cap()` | Capability bitmask |
| `netns` | `current_netns()` | Network namespace inode |
| `comm` | `bpf_get_current_comm()` | Process name (16 bytes) |
| `filename` | syscall arg0 via `bpf_probe_read_user_str` | Executable path being exec'd |

---

## BPF Maps

### `process_events` (perf event array)

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} process_events SEC(".maps");
```

Output channel — one entry per CPU. `loader.go` opens this map as a `PerfBufferReader`.

### `process_heap` (per-CPU array)

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct process_event));
    __uint(max_entries, 1);
} process_heap SEC(".maps");
```

Per-CPU scratch buffer. `process_event` (281 bytes) fits within the 512-byte BPF stack but is allocated here to avoid stack pressure when the function call chain deepens.

---

## Tracepoints

### `sys_enter_execve` / `sys_enter_execveat`

```c
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx)
```

Both tracepoints call the shared `emit_exec_event(ctx, filename_arg_index)` helper:

1. Look up per-CPU `process_heap[0]` — zero-initialise on first access
2. Fill `pid`, `ppid`, `uid`, `gid`, `cap_effective`, `netns`, `comm`
3. `bpf_probe_read_user_str(event->filename, ...)` from `ctx->args[filename_arg_index]`
4. `SUBMIT_EVENT(process_events, event, sizeof(*event))`

`execve` passes filename at `args[0]`; `execveat` passes it at `args[1]` (after the dirfd).

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](../types.md) | `ProcessEvent` Go struct mirrors `process_event` |
| [pkg/ebpf/process_monitor.go](../monitors.md) | Reads `process_events` perf buffer, decodes with `binary.Read` |
| [common.h](./common_h.md) | `current_pid_tgid`, `current_cap`, `current_netns`, `SUBMIT_EVENT` |
