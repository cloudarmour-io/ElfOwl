// ANCHOR: Network Monitor eBPF Program - Mar 25, 2026
// Restores TCP tuple fidelity via tracepoint/tcp/tcp_connect.

#include "common.h"

// Event layout must match pkg/ebpf/types.go: NetworkEvent.
struct network_event {
	__u32 pid;
	__u16 family;
	__u16 sport;
	__u16 dport;
	__u32 saddr;
	__u32 daddr;
	__u8 protocol;
	__u64 cgroup_id;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} network_events SEC(".maps");

static __always_inline __u32 pack_ipv4(const __u8 addr[4])
{
	return ((__u32)addr[0]) |
	       ((__u32)addr[1] << 8) |
	       ((__u32)addr[2] << 16) |
	       ((__u32)addr[3] << 24);
}

SEC("tracepoint/tcp/tcp_connect")
int network_monitor(struct trace_event_raw_tcp_event_sk *ctx)
{
	struct network_event evt = {};

	if (ctx->family != AF_INET) {
		return 0;
	}

	evt.pid = current_pid();
	evt.family = ctx->family;
	evt.sport = ctx->sport;
	evt.dport = ctx->dport;
	evt.saddr = pack_ipv4(ctx->saddr);
	evt.daddr = pack_ipv4(ctx->daddr);
	evt.protocol = IPPROTO_TCP;
	evt.cgroup_id = bpf_get_current_cgroup_id();

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
