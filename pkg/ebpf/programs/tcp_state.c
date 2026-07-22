// ANCHOR: TCP State Tracker - Feature: kernel state transitions - Jul 22, 2026
// Hooks tcp_set_state tracepoint to capture TCP state changes
// Maps kernel states to flow state machine for accurate connection tracking

#include "common.h"

// Flow state constants (must match Go definitions)
#define FLOW_STATE_NEW         1
#define FLOW_STATE_ESTABLISHED 2
#define FLOW_STATE_CLOSING     3
#define FLOW_STATE_CLOSED      4

// TCP state transition event
struct tcp_state_event {
    __u64 timestamp;
    __u32 pid;
    __u32 old_state;
    __u32 new_state;
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 family;  // AF_INET or AF_INET6
};

// Perf buffer for TCP state events (defined via libbpf helpers)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_ARRAY);
} tcp_state_events SEC(".maps");

// Helper: Map TCP state to flow state
static __always_inline int tcp_to_flow_state(__u32 tcp_state) {
    // TCP state constants from vmlinux.h
    switch (tcp_state) {
        case TCP_ESTABLISHED:
            return FLOW_STATE_ESTABLISHED;
        case TCP_SYN_SENT:
        case TCP_SYN_RECV:
            return FLOW_STATE_NEW;
        case TCP_FIN_WAIT1:
        case TCP_FIN_WAIT2:
        case TCP_CLOSE_WAIT:
        case TCP_LAST_ACK:
        case TCP_CLOSING:
            return FLOW_STATE_CLOSING;
        case TCP_CLOSE:
        case TCP_TIME_WAIT:
            return FLOW_STATE_CLOSED;
        case TCP_LISTEN:
        default:
            return 0;  // Ignore
    }
}

// ANCHOR: tcp_set_state tracepoint hook - Feature: kernel TCP state tracking - Jul 22, 2026
// Captures TCP state transitions from kernel and exports via perf buffer
SEC("tp/tcp/tcp_set_state")
int trace_tcp_set_state(struct trace_event_raw_tcp_event_sk_skaddr *ctx) {
    struct tcp_state_event *event;

    // Allocate perf event buffer
    event = bpf_ringbuf_reserve(&tcp_state_events, sizeof(*event), 0);
    if (!event) {
        return 0;
    }

    // Fill in basic event info
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_uid() >> 32;
    event->old_state = ctx->oldstate;
    event->new_state = ctx->newstate;

    // Ignore LISTEN state (server side, not relevant for client-side flow tracking)
    if (ctx->newstate == TCP_LISTEN) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }

    // Extract connection tuple from socket
    struct sock_common *sk = (struct sock_common *)ctx->skaddr;

    // Read address family using CO-RE (Compile Once, Run Everywhere)
    event->family = BPF_CORE_READ(sk, family);

    if (event->family == AF_INET) {
        // IPv4: read 4-tuple
        event->saddr = BPF_CORE_READ(sk, skc_rcv_saddr);
        event->daddr = BPF_CORE_READ(sk, skc_daddr);
        event->sport = BPF_CORE_READ(sk, skc_num);
        event->dport = bpf_ntohs(BPF_CORE_READ(sk, skc_dport));
    }

    // Submit event to ring buffer
    bpf_ringbuf_submit(event, 0);
    return 0;
}
