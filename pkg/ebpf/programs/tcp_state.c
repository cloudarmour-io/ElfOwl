// ANCHOR: TCP State Tracker - Feature: kernel state transitions - Jul 22, 2026
// Minimal kprobe hook on tcp_set_state to capture TCP state changes

#include "common.h"

struct tcp_state_event {
    __u64 timestamp;
    __u32 new_state;
    __u16 family;
    __u16 reserved;
    __u32 source_ip;
    __u32 destination_ip;
    __u8 source_ip_v6[16];
    __u8 destination_ip_v6[16];
    __u16 source_port;
    __u16 destination_port;
    __u32 netns_id;
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
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
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
	if (sk) {
		event->family = BPF_CORE_READ(sk, __sk_common.skc_family);
		if (event->family == AF_INET6) {
			BPF_CORE_READ_INTO(event->source_ip_v6, sk, __sk_common.skc_v6_rcv_saddr);
			BPF_CORE_READ_INTO(event->destination_ip_v6, sk, __sk_common.skc_v6_daddr);
		} else {
			event->source_ip = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
			event->destination_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
		}
		event->source_port = BPF_CORE_READ(sk, __sk_common.skc_num);
		event->destination_port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		struct net *net = BPF_CORE_READ(sk, __sk_common.skc_net.net);
		if (net)
			event->netns_id = BPF_CORE_READ(net, ns.inum);
	}

    bpf_ringbuf_submit(event, 0);
    return 0;
}
