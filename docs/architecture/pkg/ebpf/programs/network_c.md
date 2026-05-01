# `pkg/ebpf/programs/network.c` — Network Connection Monitor

**Path:** `pkg/ebpf/programs/network.c`
**Lines:** 292
**Output:** `bin/network.o`
**Includes:** `common.h`

---

## Overview

Captures TCP connection and state-change events, plus UDP sendto events. Covers both outbound TCP connects and inbound accept completions via the `inet_sock_set_state` hook.

---

## Data Structures

### `network_event`

```c
struct network_event {
    u32 pid;
    u32 uid;
    u32 gid;
    u64 cap_effective;
    u32 netns;
    char comm[16];
    u32  src_ip;
    u32  dst_ip;
    u16  src_port;
    u16  dst_port;
    u8   protocol;
    u8   direction;   // 0=outbound, 1=inbound
    u8   tcp_state;
    u8   _pad;
    char src_ip_str[16];
    char dst_ip_str[16];
};
```

| Field | Description |
|---|---|
| `src_ip` / `dst_ip` | IPv4 addresses in network byte order |
| `src_ip_str` / `dst_ip_str` | Dotted-decimal string form (filled by `pack_ipv4`) |
| `protocol` | `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17) |
| `direction` | `0` = outbound (SYN sent), `1` = inbound (server-side accept) |
| `tcp_state` | TCP state code at `inet_sock_set_state` fire time |

---

## BPF Maps

### `network_events` (perf event array)

Output perf buffer. Read by `NetworkMonitor` in Go.

### `network_heap` (per-CPU array, 1 entry)

Per-CPU scratch for `network_event` — avoids stack pressure.

---

## Helper Functions

### `pack_ipv4(u32 ip, char *buf, int buf_size)`

Formats a 32-bit IPv4 address (network byte order) into a dotted-decimal string using integer arithmetic (no `snprintf` — not available in BPF). Writes into `buf`.

### `read_udp_destination(ctx, event)`

Reads the `sockaddr_in` destination passed to `sendto(2)` from userspace via `bpf_probe_read_user`. Fills `dst_ip`, `dst_port`, `dst_ip_str`.

### `infer_direction(struct sock *sk)`

Reads `sk->sk_state` via `BPF_CORE_READ`. Returns `0` (outbound) if state is `TCP_SYN_SENT`, `1` (inbound) otherwise.

---

## Tracepoints

### `tcp/tcp_connect`

```c
SEC("tracepoint/tcp/tcp_connect")
int handle_tcp_connect(struct trace_event_raw_tcp_event_sk *ctx)
```

Fires on active TCP connect initiation. Reads `sock` fields via CO-RE:
- `sk->__sk_common.skc_family` — must be `AF_INET`
- `sk->__sk_common.skc_rcv_saddr` / `skc_daddr` — src/dst IP
- `sk->__sk_common.skc_num` / `skc_dport` — src/dst port
- `direction = 0` (outbound)

Drops non-IPv4 events silently.

### `sock/inet_sock_set_state`

```c
SEC("tracepoint/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
```

Fires on every TCP state transition. Only processes transitions into `TCP_ESTABLISHED` to capture inbound accept completions:

```c
if (ctx->newstate != TCP_ESTABLISHED) return 0;
```

Uses `ctx->family`, `ctx->sport`, `ctx->dport`, `ctx->saddr`, `ctx->daddr` directly from the tracepoint args (no CO-RE needed — tracepoint format fields are stable).

`direction = infer_direction(ctx->skaddr)` — distinguishes client vs server side.

### `syscalls/sys_enter_sendto`

```c
SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
```

Captures UDP sendto calls. Reads `sockaddr __user *dest_addr` from `ctx->args[4]`. Calls `read_udp_destination` to extract destination. Sets `protocol = IPPROTO_UDP`, `direction = 0`.

---

## Related Files

| File | Relationship |
|---|---|
| [pkg/ebpf/types.go](../types.md) | `NetworkEvent` Go struct mirrors `network_event` |
| [pkg/ebpf/network_monitor.go](../monitors.md) | Reads events, calls `networkDirection`, `tcpStateName` |
| [common.h](./common_h.md) | Shared includes, `current_pid_tgid`, `SUBMIT_EVENT` |
