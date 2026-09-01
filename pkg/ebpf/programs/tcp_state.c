// ANCHOR: TCP State Tracker - Feature: kernel state transitions - Jul 22, 2026
// Minimal kprobe hook on tcp_set_state to capture TCP state changes

#include "common.h"

struct tcp_state_event {
    __u64 timestamp;
    __u32 new_state;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tcp_state_events SEC(".maps");

// ANCHOR: kprobe hook for tcp_set_state - Feature: kernel TCP state tracking - Jul 22, 2026
// Minimal hook that captures TCP state transitions from kernel
// Signature: void tcp_set_state(struct sock *sk, int state)
// x86-64 calling convention: rdi=sk, rsi=state
SEC("kprobe/tcp_set_state")
int trace_tcp_set_state(struct pt_regs *ctx) {
    __u32 new_state = (__u32)PT_REGS_PARM2(ctx);

    // Filter out invalid states and LISTEN (server-side)
    // Valid states: SYN_SENT(2), SYN_RECV(3), ESTABLISHED(1), FIN_WAIT*(4-5), CLOSING(11), CLOSE_WAIT(8), LAST_ACK(9), TIME_WAIT(6), CLOSE(7)
    if (new_state == 0 || new_state > 11 || new_state == 10)  // Skip LISTEN(10) and invalid
        return 0;

    struct tcp_state_event *event = bpf_ringbuf_reserve(&tcp_state_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->timestamp = bpf_ktime_get_ns();
    event->new_state = new_state;

    bpf_ringbuf_submit(event, 0);
    return 0;
}
