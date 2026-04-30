# `pkg/ebpf/programs/capability.c` — Linux Capability Monitor

**Package:** `ebpf` (C source)
**Path:** `pkg/ebpf/programs/capability.c`
**Lines:** 651
**Output:** `bin/capability.o`
**Includes:** `common.h`

---

## Overview

Captures Linux capability usage events. Attaches to two tracepoints:

1. `capability/cap_capable` — fires when the kernel evaluates a capability check
2. `raw_syscalls/sys_enter` — tracks per-PID syscall IDs to attribute capability checks to the originating syscall, and provides a `mount(2)` fallback on kernels where `cap_capable` may not fire

---

## Data Structures

### `capability_event`

```c
struct capability_event {
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cap_effective;
    u32 netns;
    char comm[16];
    int  cap;         // capability number (e.g. CAP_NET_ADMIN=12, CAP_SYS_ADMIN=21)
    int  syscall_id;  // syscall that triggered the check
    u8   audit;       // 1 = audited check, 0 = silent probe
    u8   _pad[3];
};
```

---

## BPF Maps

### `capability_events` (perf event array)

Output perf buffer. Read by `CapabilityMonitor` in Go.

### `capability_heap` (per-CPU array, 1 entry)

Per-CPU scratch for `capability_event`.

### `capability_syscalls` (LRU hash map)

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key,   u32);   // pid (TGID)
    __type(value, u32);   // most recent syscall_id for this pid
} capability_syscalls SEC(".maps");
```

Stores the last syscall entered by each PID. When `cap_capable` fires inside the kernel (without direct syscall context), the handler looks up this map to record which syscall triggered the capability check. LRU eviction handles process exits without explicit cleanup.

---

## Helper Functions

### `emit_capability_event(ctx, cap, syscall_id, audit)`

```c
static __always_inline int emit_capability_event(
    void *ctx, int cap, int syscall_id, u8 audit)
```

1. Looks up per-CPU `capability_heap[0]`
2. Fills `pid`, `uid`, `gid`, `cap_effective`, `netns`, `comm`
3. Sets `cap`, `syscall_id`, `audit`
4. Submits to `capability_events` via `SUBMIT_EVENT`

---

## Tracepoints

### `capability/cap_capable`

```c
SEC("tracepoint/capability/cap_capable")
int handle_cap_capable(struct trace_event_raw_cap_capable *ctx)
```

Fires when the kernel evaluates `capable()` or `ns_capable()`.

- `ctx->cap` — capability number being checked
- `ctx->audit` — whether this is an audited check

Processing:
1. Filter: only emit events where `ctx->audit == 1` — silent permission probes are dropped to reduce noise
2. Look up `capability_syscalls[current_pid]` → `syscall_id` (0 if absent)
3. Call `emit_capability_event(ctx, ctx->cap, syscall_id, ctx->audit)`

### `raw_syscalls/sys_enter`

```c
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_raw_sys_enter(struct trace_event_raw_sys_enter *ctx)
```

Fires on every syscall entry. Serves two purposes:

**1. Syscall ID tracking:**
```c
u32 pid = bpf_get_current_pid_tgid() >> 32;
u32 id  = (u32)ctx->id;
bpf_map_update_elem(&capability_syscalls, &pid, &id, BPF_ANY);
```
Records the current syscall for later attribution when `cap_capable` fires.

**2. `mount(2)` fallback:**
On some kernels `cap_capable` does not fire for `CAP_SYS_ADMIN` checks during `mount(2)`. When `ctx->id == __NR_mount`:
```c
emit_capability_event(ctx, CAP_SYS_ADMIN, __NR_mount, 1);
```
Synthesises a `CAP_SYS_ADMIN` event for every `mount` syscall as a best-effort signal.

---

## Design Notes

- The `raw_syscalls/sys_enter` + LRU map pattern is a standard eBPF technique for correlating kernel-internal capability checks (which lack direct syscall context) back to the originating userspace call.
- `max_entries = 10240` is sized to handle high-concurrency workloads without LRU thrash under normal conditions.
- `audit == 1` filtering reduces event volume significantly — most `capable()` calls in the kernel are silent probes that never count as real usage.

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](../types.md) | `CapabilityEvent` Go struct mirrors `capability_event` |
| [pkg/ebpf/capability_monitor.go](../monitors.md) | Reads events, calls `capabilityName` helper |
| [common.h](./common_h.md) | `current_cap`, `current_netns`, `SUBMIT_EVENT`, `__NR_mount` definition |
