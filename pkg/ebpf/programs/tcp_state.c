// ANCHOR: TCP State Tracker - Feature: kernel state transitions - Jul 22, 2026
// Hooks tcp_set_state tracepoint to capture TCP state changes
// Maps kernel states to flow state machine for accurate connection tracking

#include "common.h"

// TCP state constants (from include/net/tcp_states.h)
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT = 2,
    TCP_SYN_RECV = 3,
    TCP_FIN_WAIT1 = 4,
    TCP_FIN_WAIT2 = 5,
    TCP_TIME_WAIT = 6,
    TCP_CLOSE = 7,
    TCP_CLOSE_WAIT = 8,
    TCP_LAST_ACK = 9,
    TCP_LISTEN = 10,
    TCP_CLOSING = 11,
};

// Flow state constants
enum {
    FLOW_STATE_NEW = 1,
    FLOW_STATE_ESTABLISHED = 2,
    FLOW_STATE_CLOSING = 3,
    FLOW_STATE_CLOSED = 4,
};

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

// Perf buffer for TCP state events
BPF_PERF_OUTPUT(tcp_state_events);

// Helper: Map TCP state to flow state
static __always_inline int tcp_to_flow_state(__u32 tcp_state) {
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

// tcp_set_state tracepoint hook
TRACEPOINT_PROBE(tcp, tcp_set_state) {
    struct tcp_state_event event = {
        .timestamp = bpf_ktime_get_ns(),
        .pid = bpf_get_current_pid_uid() >> 32,
        .old_state = args->oldstate,
        .new_state = args->newstate,
    };

    // Extract connection tuple from socket structure
    // This varies by kernel version; CO-RE helpers handle variations
    struct sock *sk = (struct sock *)args->skaddr;

    // Read socket address family
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);

    event.family = family;

    if (family == AF_INET) {
        // IPv4
        __u32 saddr = 0, daddr = 0;
        __u16 sport = 0, dport = 0;

        bpf_probe_read_kernel(&saddr, sizeof(saddr), &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&sport, sizeof(sport), &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);

        event.saddr = saddr;
        event.daddr = daddr;
        event.sport = sport;
        event.dport = ntohs(dport);  // Network byte order to host
    }

    // Ignore LISTEN state (server side)
    if (args->newstate == TCP_LISTEN) {
        return 0;
    }

    tcp_state_events.perf_submit(args, &event, sizeof(event));
    return 0;
}
