// ANCHOR: Network Monitor eBPF Program - Mar 23, 2026
// Captures TCP connection activity via sys_enter_connect.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct sys_enter_connect_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long fd;
	const struct sockaddr *uservaddr;
	long addrlen;
};

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

#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

static __always_inline int read_ipv4_sockaddr(const struct sockaddr *uaddr, __u16 addr_len,
					       __u16 *family, __u16 *dport, __u32 *daddr)
{
	struct sockaddr_in dst = {};

	if (!uaddr || addr_len < sizeof(dst)) {
		return -1;
	}

	if (bpf_probe_read_user(&dst, sizeof(dst), uaddr) < 0) {
		return -1;
	}

	if (dst.sin_family != AF_INET) {
		return -1;
	}

	*family = dst.sin_family;
	*dport = bpf_ntohs(dst.sin_port);
	*daddr = dst.sin_addr.s_addr;
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int network_monitor(struct sys_enter_connect_ctx *ctx)
{
	void *tp_ctx = ctx;
	const struct sockaddr *dst_addr = ctx->uservaddr;
	__u16 dst_len = (__u16)ctx->addrlen;
	__u16 family = 0;
	__u16 dport = 0;
	__u32 daddr = 0;
	struct network_event evt = {};

	if (read_ipv4_sockaddr(dst_addr, dst_len, &family, &dport, &daddr) < 0) {
		return 0;
	}

	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.family = family;
	evt.sport = 0;
	evt.dport = dport;
	evt.saddr = 0;
	evt.daddr = daddr;
	evt.protocol = IPPROTO_TCP;
	evt.cgroup_id = bpf_get_current_cgroup_id();

	bpf_perf_event_output(tp_ctx, &network_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
