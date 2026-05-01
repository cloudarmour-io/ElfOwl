# `pkg/ebpf/programs/tls.c` — TLS ClientHello Monitor

**Package:** `ebpf` (C source)
**Path:** `pkg/ebpf/programs/tls.c`
**Lines:** 1032
**Output:** `bin/tls.o`
**Includes:** `common.h`

---

## Overview

Captures TLS ClientHello messages by intercepting write-family syscalls. Validates the payload with strict protocol checks, copies up to 2048 bytes of TLS record data into the event, and resolves the destination port via a CO-RE walk through the task's file descriptor table.

Four tracepoints cover the full set of write-path syscalls used by different TLS implementations:

| Tracepoint | Used by |
|---|---|
| `sys_enter_write` | OpenSSL, GnuTLS (synchronous write) |
| `sys_enter_sendto` | async I/O paths |
| `sys_enter_writev` | scatter-gather writes |
| `sys_enter_sendmsg` | Go `crypto/tls` |

---

## Data Structures

### `tls_client_hello_event`

```c
struct tls_client_hello_event {
    u32  pid;
    u32  uid;
    u32  gid;
    u64  cap_effective;
    u32  netns;
    char comm[16];
    u32  dst_ip;
    u16  dst_port;
    u16  length;          // actual bytes copied into metadata[]
    u8   metadata[2048];  // raw TLS ClientHello bytes
} __attribute__((packed));
```

**`__attribute__((packed))`** eliminates struct alignment padding. This makes the C memory layout differ from a Go struct with the same fields — `binary.Read` cannot be used to decode it. `DecodeTLSEvent()` in `pkg/ebpf/types.go` performs manual offset-based decoding.

**Total size:** `4+4+4+8+4+16+4+2+2+2048 = 2096 bytes` — exceeds the 512-byte BPF stack limit. The `tls_scratch` per-CPU map is used as a heap allocation.

### `tls_user_msghdr`

```c
struct tls_user_msghdr {
    void        *msg_name;
    int          msg_namelen;
    struct iovec *msg_iov;
    size_t        msg_iovlen;
    void        *msg_control;
    size_t        msg_controllen;
    int           msg_flags;
};
```

Manual POSIX `msghdr` definition matching the **userspace** ABI. The kernel `struct msghdr` from `vmlinux.h` has a different layout — using it to read a userspace `msghdr *` pointer would produce garbage. This struct is used only in `handle_sendmsg` to extract `iov` vectors from the user buffer.

---

## BPF Maps

### `tls_events` (perf event array)

Output perf buffer — one entry per CPU. Read by `TLSMonitor` in Go.

### `tls_scratch` (per-CPU array, 1 entry)

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct tls_client_hello_event));
    __uint(max_entries, 1);
} tls_scratch SEC(".maps");
```

Per-CPU heap for `tls_client_hello_event`. The BPF verifier rejects any attempt to allocate 2096 bytes on the stack (limit: 512 bytes). A per-CPU array with one slot is the standard eBPF workaround — each CPU has its own slot so no locking is needed.

---

## Helper Functions

### `is_tls_client_hello(buf, len) bool`

Strict 3-field validation on the raw user buffer:

| Offset | Check | Expected |
|---|---|---|
| `[0]` | TLS record type | `0x16` (Handshake) |
| `[1..2]` | Legacy record version | `0x0301` (TLS 1.0) or `0x0303` (TLS 1.2) |
| `[5]` | Handshake message type | `0x01` (ClientHello) |

Returns `false` immediately on any mismatch or if `len < 6`. All reads are via `bpf_probe_read_user` — the buffer lives in userspace.

### `copy_tls_metadata(event, buf, buf_len)`

Copies `min(buf_len, 2048)` bytes from userspace `buf` into `event->metadata` via `bpf_probe_read_user`. Sets `event->length` to actual bytes copied. An explicit `& 0x7FF` mask on the length argument satisfies the BPF verifier's bounds requirement.

### `fd_dst_port(fd) u16`

Resolves a file descriptor number to the destination TCP port via a CO-RE walk:

```
current_task
  → files         (task_struct.files → files_struct)
    → fdt         (files_struct.fdt → fdtable)
      → fd[n]     (fdtable.fd → file *)
        → private_data  (file.private_data → socket *)
          → sk    (socket.sk → sock *)
            → __sk_common.skc_dport   (u16, network byte order)
```

Each dereference uses `BPF_CORE_READ`. Returns `0` on any null pointer or if `fd` is out of range for the `fdt->max_fds` bound.

### `fd_family(fd) u16`

Same CO-RE walk as `fd_dst_port` but reads `sk->__sk_common.skc_family`. Returns the address family (`AF_INET` = 2, `AF_INET6` = 10). Called before `fd_dst_port` to skip non-socket fds.

### `fill_tls_event(ctx, event, buf, buf_len, fd) int`

Orchestrates full event population:

1. `is_tls_client_hello(buf, buf_len)` → return `-1` if not a ClientHello
2. Fill `pid`, `uid`, `gid`, `cap_effective`, `netns`, `comm`
3. `event->dst_port = fd_dst_port(fd)`
4. `copy_tls_metadata(event, buf, buf_len)`
5. Submit to `tls_events`

Returns `0` on success, `-1` if validation failed.

---

## Tracepoints

### `syscalls/sys_enter_write`

```c
SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx)
```

- `fd = ctx->args[0]`, `buf = (u8 *)ctx->args[1]`, `count = ctx->args[2]`
- Looks up per-CPU `tls_scratch[0]`
- Calls `fill_tls_event(ctx, event, buf, count, fd)`

### `syscalls/sys_enter_sendto`

Same structure as `write`. `fd = ctx->args[0]`, `buf = ctx->args[1]`, `len = ctx->args[2]`.

### `syscalls/sys_enter_writev`

`writev` passes a `struct iovec __user *` rather than a flat buffer:

1. Read first `iovec` from userspace: `bpf_probe_read_user(&iov0, sizeof(iov0), ctx->args[1])`
2. Use `iov0.iov_base` as `buf`, `iov0.iov_len` as `len`
3. Call `fill_tls_event` on the first iov segment only

Only the first segment is inspected — TLS records are not split across iov entries in practice.

### `syscalls/sys_enter_sendmsg`

Used by Go's `crypto/tls`. `sendmsg` passes a `struct msghdr __user *`:

1. `bpf_probe_read_user(&msghdr, sizeof(tls_user_msghdr), ctx->args[1])` — read user-ABI msghdr
2. Read first `iovec` from `msghdr.msg_iov`
3. Use `iov[0].iov_base` / `iov[0].iov_len` as buf/len
4. Call `fill_tls_event`

**Why `tls_user_msghdr` not `vmlinux.h`'s `struct msghdr`?** The in-kernel `msghdr` has different field ordering than the POSIX userspace layout. Reading a userspace pointer with the kernel type definition produces incorrect field values.

---

## Design Constraints Summary

| Constraint | Solution |
|---|---|
| 2096-byte event exceeds 512-byte BPF stack | `tls_scratch` per-CPU array map as heap |
| `__packed` C struct ≠ Go struct alignment | `DecodeTLSEvent()` manual offset decode in `types.go` |
| Go `crypto/tls` uses `sendmsg`, not `write` | `sys_enter_sendmsg` fourth tracepoint |
| fd → port requires kernel struct traversal | `fd_dst_port()` CO-RE task→files→socket→sk walk |
| Userspace `msghdr` ≠ kernel `msghdr` | `tls_user_msghdr` manual POSIX struct definition |

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](../types.md) | `TLSClientHelloEvent`, `DecodeTLSEvent` — handles packed layout |
| [pkg/ebpf/tls_monitor.go](../tls_monitor.md) | Reads events, runs cert probing and JA3 parsing |
| [common.h](./common_h.md) | CO-RE includes, `current_cap`, `current_netns`, `SUBMIT_EVENT` |
