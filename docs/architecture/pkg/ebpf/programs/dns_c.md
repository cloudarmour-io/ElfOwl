# `pkg/ebpf/programs/dns.c` — DNS Query Monitor

**Path:** `pkg/ebpf/programs/dns.c`
**Lines:** 320
**Output:** `bin/dns.o`
**Includes:** Raw Linux headers (does NOT include `common.h`)

---

## Overview

Captures DNS queries by intercepting UDP `sendto` syscalls (query sent) and correlating them with the subsequent `recvfrom` reply (to extract query type and response code from the DNS wire format).

Uses an LRU hash map to track in-flight DNS transactions keyed on `(pid, fd)`.

---

## Why Not `common.h`?

`dns.c` includes raw Linux BPF headers directly:
```c
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
```
This was the original implementation style before `common.h` was introduced. It is functionally equivalent but does not use CO-RE (`vmlinux.h`) for struct access — `dns.c` only reads syscall arguments, not kernel struct fields, so CO-RE is not needed.

---

## Data Structures

### `dns_event`

```c
struct dns_event {
    u32 pid;
    u32 uid;
    char comm[16];
    char query[256];
    u16 query_type;    // A=1, AAAA=28, CNAME=5, MX=15, TXT=16, PTR=12
    u16 rcode;         // 0=NoError, 1=FormErr, 2=ServFail, 3=NXDomain, ...
    u8  is_response;   // 0=query, 1=response
};
```

### `dns_recv_state` (LRU hash map)

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key,   u64);   // (pid << 32 | fd)
    __type(value, u8);    // fd family placeholder (unused; presence = in-flight)
} dns_recv_state SEC(".maps");
```

Tracks file descriptors that sent a DNS query. When `recvfrom` fires on a tracked fd, the DNS response is parsed.

---

## Helper Functions

### `copy_label(src, src_len, dst, dst_len, offset)`

Copies a single DNS label (length-prefixed byte sequence) from a userspace buffer into a dot-separated destination string. Advances `offset` past the label. Used iteratively to reconstruct the FQDN.

### `parse_dns_question(buf, buf_len, event)`

Reads the question section of a DNS message from userspace:
1. Iterates labels via `copy_label` until null terminator or max iterations (10)
2. Writes reconstructed FQDN into `event->query`
3. Reads 2-byte `QTYPE` after the name — stores in `event->query_type`

### `parse_dns_message(buf, buf_len, event)`

Parses the 12-byte DNS header:
- Byte offset 2–3: flags — extracts QR bit (`is_response = (flags >> 15) & 1`)
- Byte offset 2–3: lower 4 bits = RCODE → `event->rcode`
- Calls `parse_dns_question(buf + 12, ...)` for the question section

---

## Tracepoints

### `syscalls/sys_enter_sendto`

```c
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_dns_send(struct trace_event_raw_sys_enter *ctx)
```

Fires on every `sendto`. Filters to UDP port 53 by reading the `sockaddr_in` destination from `ctx->args[4]`. If `dport == 53`:
1. Records `(pid << 32 | fd)` in `dns_recv_state`
2. Reads the DNS wire payload from `ctx->args[1]` (user buffer pointer)
3. Calls `parse_dns_message` — fills query, type, rcode, is_response=0
4. Submits `dns_event` to `dns_events` perf buffer

### `syscalls/sys_enter_recvfrom`

```c
SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_dns_recv_enter(struct trace_event_raw_sys_enter *ctx)
```

Fires on `recvfrom` entry. Checks if `(pid << 32 | fd)` exists in `dns_recv_state`. If yes, stores the user buffer pointer in a second scratch map (`dns_recv_buf`) keyed on the same `(pid, fd)` tuple — for retrieval on exit.

### `syscalls/sys_exit_recvfrom`

```c
SEC("tracepoint/syscalls/sys_exit_recvfrom")
int trace_dns_recv_exit(struct trace_event_raw_sys_exit *ctx)
```

Fires on `recvfrom` return. Looks up the saved buffer pointer. If return value (`ctx->ret`) > 0:
1. Reads DNS response from the saved user buffer
2. Calls `parse_dns_message` with `is_response=1`
3. Submits `dns_event`
4. Deletes entry from `dns_recv_state`

---

## LRU Eviction

The `dns_recv_state` map holds at most 1024 entries. Entries for abandoned connections (process exits, non-DNS recvfrom on the same fd) are evicted by the kernel's LRU policy. There is no explicit cleanup beyond the `sys_exit_recvfrom` delete.

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](../types.md) | `DNSEvent` Go struct mirrors `dns_event` |
| [pkg/ebpf/dns_monitor.go](../monitors.md) | Reads events, calls `dnsQueryTypeName`, `dnsRcodeName` |
