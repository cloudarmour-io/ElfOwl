# `pkg/ebpf/programs/common.h` — Shared BPF Helpers

**Path:** `pkg/ebpf/programs/common.h`
**Lines:** 124
**Included by:** `process.c`, `network.c`, `capability.c`, `tls.c`
**NOT included by:** `dns.c`, `file.c` (use raw Linux headers directly)

---

## Overview

Header-only shared library for the eBPF C programs. Provides:
- Standard BPF and CO-RE includes
- Network protocol constants
- x86_64 syscall number definitions (architecture-guarded)
- `SUBMIT_EVENT` macro for perf buffer submission
- Inline helpers for reading current process metadata

---

## Includes

```c
#include "vmlinux.h"            // CO-RE BTF type definitions
#include <bpf/bpf_helpers.h>    // SEC(), BPF_MAP_DEF, bpf_map_lookup_elem, etc.
#include <bpf/bpf_core_read.h>  // BPF_CORE_READ(), BPF_CORE_READ_INTO()
#include <bpf/bpf_tracing.h>    // PT_REGS_*, BPF_KPROBE, BPF_KRETPROBE
```

---

## Network Constants

| Constant | Value | Meaning |
|---|---|---|
| `AF_INET` | `2` | IPv4 address family |
| `AF_INET6` | `10` | IPv6 address family |
| `IPPROTO_TCP` | `6` | TCP protocol number |
| `IPPROTO_UDP` | `17` | UDP protocol number |

---

## Syscall IDs (x86_64)

Defined only when `__TARGET_ARCH_x86` is set (controlled by `Makefile`'s `-D__TARGET_ARCH_x86` flag):

```c
#ifdef __TARGET_ARCH_x86
#define __NR_mount    165
#define __NR_execve   59
#define __NR_execveat 322
// ...
#endif
```

These are used by `capability.c` to attribute capability usage to the originating syscall.

---

## `SUBMIT_EVENT` Macro

```c
#define SUBMIT_EVENT(map, data, size)                       \
    bpf_perf_event_output(ctx, &map, BPF_F_CURRENT_CPU,    \
                          data, size)
```

Submits an event to a BPF perf buffer map on the current CPU. All five simple programs (process, network, capability, plus DNS and file through their own variants) use an equivalent perf output call.

---

## Inline Helpers

### `current_pid_tgid()`

```c
static __always_inline u64 current_pid_tgid()
```

Returns `bpf_get_current_pid_tgid()`. Upper 32 bits = TGID (process ID), lower 32 bits = TID.

### `current_uid_gid()`

```c
static __always_inline u64 current_uid_gid()
```

Returns `bpf_get_current_uid_gid()`. Upper 32 bits = GID, lower 32 bits = UID.

### `current_cap()`

```c
static __always_inline u64 current_cap()
```

Reads `current_task->cap_effective` via `BPF_CORE_READ`. Returns the effective capability bitmask of the running process.

### `current_netns()`

```c
static __always_inline u32 current_netns()
```

Reads `current_task->nsproxy->net_ns->ns.inum` via `BPF_CORE_READ`. Returns the network namespace inode number — used to correlate events to containers.

---

## Architecture Notes

- All CO-RE field reads use `BPF_CORE_READ` rather than direct pointer dereference — required for portability across kernel versions without recompilation.
- The x86_64 syscall ID guard means `common.h` is not portable to ARM64 without extending the `#ifdef` block. The `Makefile` `TARGET_ARCH` variable controls which arch definitions are active.
