// ANCHOR: Network Monitor eBPF Program - Mar 25, 2026
// Adds TCP state, UDP send tracing, IPv6 tuples, and netns metadata.

#include "common.h"

// Event layout must match pkg/ebpf/types.go: NetworkEvent.
struct network_event {
	__u32 pid;
	__u16 family;
	__u16 sport;
	__u16 dport;
	__u32 saddr;
	__u32 daddr;
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	__u8 protocol;
	__u8 direction;
	__u8 state;
	__u32 netns;
	__u64 cgroup_id;
	__u32 bytes;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} network_events SEC(".maps");

#define NET_DIR_UNKNOWN 0
#define NET_DIR_OUTBOUND 1
#define NET_DIR_INBOUND 2

struct sys_enter_sendto_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long fd;
	const char *buff;
	long len;
	long flags;
	const struct sockaddr *addr;
	long addr_len;
};

static __always_inline __u32 pack_ipv4(const __u8 addr[4])
{
	return ((__u32)addr[0]) |
	       ((__u32)addr[1] << 8) |
	       ((__u32)addr[2] << 16) |
	       ((__u32)addr[3] << 24);
}

static __always_inline int read_udp_destination(const struct sockaddr *uaddr, __u32 addr_len,
				    __u16 *family, __u16 *dport, __u32 *daddr, __u8 daddr_v6[16])
{
	struct sockaddr_in dst4 = {};
	struct sockaddr_in6 dst6 = {};

	if (!uaddr || addr_len < sizeof(dst4)) {
		return -1;
	}

	if (bpf_probe_read_user(&dst4, sizeof(dst4), uaddr) < 0) {
		return -1;
	}

	if (dst4.sin_family == AF_INET) {
		*family = dst4.sin_family;
		*dport = dst4.sin_port;
		*daddr = dst4.sin_addr.s_addr;
		return 0;
	}

	if (addr_len < sizeof(dst6)) {
		return -1;
	}

	if (bpf_probe_read_user(&dst6, sizeof(dst6), uaddr) < 0) {
		return -1;
	}

	if (dst6.sin6_family != AF_INET6) {
		return -1;
	}

	*family = dst6.sin6_family;
	*dport = dst6.sin6_port;
	__builtin_memcpy(daddr_v6, &dst6.sin6_addr, sizeof(dst6.sin6_addr));
	return 0;
}

static __always_inline __u8 infer_direction(int oldstate, int newstate)
{
	if (newstate == TCP_SYN_SENT) {
		return NET_DIR_OUTBOUND;
	}
	if (newstate == TCP_SYN_RECV || newstate == TCP_NEW_SYN_RECV) {
		return NET_DIR_INBOUND;
	}
	return NET_DIR_UNKNOWN;
}

// ANCHOR: Network state + UDP coverage - Feature: advanced network telemetry - Mar 25, 2026
// Emits connection tuples from tcp_connect, inet_sock_set_state, and UDP sendto.
SEC("tracepoint/tcp/tcp_connect")
int network_monitor(struct trace_event_raw_tcp_event_sk *ctx)
{
	struct network_event evt = {};
	struct trace_event_raw_tcp_event_sk tcp = {};

	if (bpf_probe_read_kernel(&tcp, sizeof(tcp), ctx) < 0) {
		return 0;
	}

	if (tcp.family != AF_INET && tcp.family != AF_INET6) {
		return 0;
	}

	evt.pid = current_pid();
	evt.family = tcp.family;
	evt.sport = tcp.sport;
	evt.dport = tcp.dport;
	evt.protocol = IPPROTO_TCP;
	evt.direction = NET_DIR_OUTBOUND;
	evt.state = 0;
	evt.netns = current_netns_inum();
	evt.cgroup_id = bpf_get_current_cgroup_id();

	if (tcp.family == AF_INET) {
		evt.saddr = pack_ipv4(tcp.saddr);
		evt.daddr = pack_ipv4(tcp.daddr);
	} else {
		__builtin_memcpy(evt.saddr_v6, tcp.saddr_v6, sizeof(evt.saddr_v6));
		__builtin_memcpy(evt.daddr_v6, tcp.daddr_v6, sizeof(evt.daddr_v6));
	}

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

// SEC("tracepoint/inet_sock/inet_sock_set_state")
SEC("tracepoint/sock/inet_sock_set_state")
int network_state_monitor(struct trace_event_raw_inet_sock_set_state *ctx)
{
	struct network_event evt = {};
	struct trace_event_raw_inet_sock_set_state sk_state = {};

	if (bpf_probe_read_kernel(&sk_state, sizeof(sk_state), ctx) < 0) {
		return 0;
	}

	if (sk_state.family != AF_INET && sk_state.family != AF_INET6) {
		return 0;
	}

	evt.pid = current_pid();
	evt.family = sk_state.family;
	evt.sport = sk_state.sport;
	evt.dport = sk_state.dport;
	evt.protocol = (__u8)sk_state.protocol;
	evt.direction = infer_direction(sk_state.oldstate, sk_state.newstate);
	evt.state = (__u8)sk_state.newstate;
	evt.netns = current_netns_inum();
	evt.cgroup_id = bpf_get_current_cgroup_id();

	if (sk_state.family == AF_INET) {
		evt.saddr = pack_ipv4(sk_state.saddr);
		evt.daddr = pack_ipv4(sk_state.daddr);
	} else {
		__builtin_memcpy(evt.saddr_v6, sk_state.saddr_v6, sizeof(evt.saddr_v6));
		__builtin_memcpy(evt.daddr_v6, sk_state.daddr_v6, sizeof(evt.daddr_v6));
	}

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int network_udp_send(struct sys_enter_sendto_ctx *ctx)
{
	struct network_event evt = {};
	struct sys_enter_sendto_ctx sendto = {};
	__u16 family = 0;
	__u16 dport = 0;
	__u32 daddr = 0;
	__u8 daddr_v6[16] = {};

	if (bpf_probe_read_kernel(&sendto, sizeof(sendto), ctx) < 0) {
		return 0;
	}

	if (read_udp_destination(sendto.addr, (__u32)sendto.addr_len, &family, &dport, &daddr, daddr_v6) < 0) {
		return 0;
	}

	evt.pid = current_pid();
	evt.family = family;
	evt.sport = 0;
	evt.dport = dport;
	evt.saddr = 0;
	evt.daddr = daddr;
	evt.protocol = IPPROTO_UDP;
	evt.direction = NET_DIR_OUTBOUND;
	evt.state = 0;
	evt.netns = current_netns_inum();
	evt.cgroup_id = bpf_get_current_cgroup_id();
	evt.bytes = sendto.len > 0 ? (__u32)sendto.len : 0;
	__builtin_memcpy(evt.daddr_v6, daddr_v6, sizeof(evt.daddr_v6));

	SUBMIT_EVENT(ctx, network_events, &evt);
	return 0;
}

#define TC_ACT_OK 0

static __always_inline int tc_l3_offset(struct __sk_buff *ctx, __u16 *offset, __u16 *protocol)
{
	__u8 eth[22] = {};
	__u16 eth_proto;
	__u16 cursor = 14;
	__u16 skb_protocol = bpf_ntohs(ctx->protocol);
	int i;

	// TUN and similar devices expose an IP packet without an Ethernet header.
	if (skb_protocol == 0x0800 || skb_protocol == 0x86dd) {
		*offset = 0;
		*protocol = skb_protocol;
		return 0;
	}
	if (bpf_skb_load_bytes(ctx, 0, eth, sizeof(eth)) < 0)
		return -1;
	__builtin_memcpy(&eth_proto, &eth[12], sizeof(eth_proto));
	eth_proto = bpf_ntohs(eth_proto);
	#pragma unroll
	for (i = 0; i < 2; i++) {
		if (eth_proto != 0x8100 && eth_proto != 0x88a8)
			break;
		__builtin_memcpy(&eth_proto, &eth[cursor], sizeof(eth_proto));
		eth_proto = bpf_ntohs(eth_proto);
		cursor += 4;
	}
	*offset = cursor;
	*protocol = eth_proto;
	return 0;
}

static __always_inline int emit_tc_ipv4(struct __sk_buff *ctx, __u8 direction)
{
	__u8 ip[20] = {};
	struct network_event evt = {};
	__u8 ihl, protocol;
	__u16 source_port = 0, destination_port = 0;
	__u32 source_ip, destination_ip;
	__u16 total_length, fragment;
	__u16 l3_offset, l3_protocol;

	if (tc_l3_offset(ctx, &l3_offset, &l3_protocol) < 0 || l3_protocol != 0x0800)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(ctx, l3_offset, ip, sizeof(ip)) < 0)
		return TC_ACT_OK;
	ihl = (ip[0] & 0x0f) * 4;
	if (ihl < 20 || (ip[9] != IPPROTO_TCP && ip[9] != IPPROTO_UDP))
		return TC_ACT_OK;
	__builtin_memcpy(&fragment, &ip[6], sizeof(fragment));
	if ((bpf_ntohs(fragment) & 0x1fff) != 0)
		return TC_ACT_OK;
	protocol = ip[9];
	__builtin_memcpy(&total_length, &ip[2], sizeof(total_length));
	__builtin_memcpy(&source_ip, &ip[12], sizeof(source_ip));
	__builtin_memcpy(&destination_ip, &ip[16], sizeof(destination_ip));
	if (bpf_skb_load_bytes(ctx, l3_offset + ihl, &source_port, sizeof(source_port)) < 0 ||
	    bpf_skb_load_bytes(ctx, l3_offset + ihl + 2, &destination_port, sizeof(destination_port)) < 0)
		return TC_ACT_OK;

	// TC runs in softirq context; process identity is not attributable to this packet.
	evt.pid = 0;
	evt.family = AF_INET;
	evt.sport = bpf_ntohs(source_port);
	evt.dport = bpf_ntohs(destination_port);
	evt.saddr = source_ip;
	evt.daddr = destination_ip;
	evt.protocol = protocol;
	evt.direction = direction;
	evt.state = 0;
	evt.netns = current_netns_inum();
	evt.cgroup_id = 0;
	if (bpf_ntohs(total_length) > ihl)
		evt.bytes = bpf_ntohs(total_length) - ihl;
	SUBMIT_EVENT(ctx, network_events, &evt);
	return TC_ACT_OK;
}

// ANCHOR: TC IPv6 parser - Feature: IPv6 forwarding telemetry with bounded extension headers - Jul 26, 2026
static __always_inline int emit_tc_ipv6(struct __sk_buff *ctx, __u8 direction)
{
	__u8 ip[40] = {};
	__u8 ext[8] = {};
	struct network_event evt = {};
	__u16 eth_proto;
	__u8 protocol;
	__u16 source_port = 0, destination_port = 0, payload_length;
	__u16 transport_offset;
	__u16 payload_end;
	__u16 ext_len;
	__u8 header_type;
	__u16 fragment;
	__u16 l3_offset, l3_protocol;
	int i;

	if (tc_l3_offset(ctx, &l3_offset, &l3_protocol) < 0 || l3_protocol != 0x86dd)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(ctx, l3_offset, ip, sizeof(ip)) < 0)
		return TC_ACT_OK;
	protocol = ip[6];
	__builtin_memcpy(&payload_length, &ip[4], sizeof(payload_length));
	transport_offset = l3_offset + sizeof(ip);
	payload_end = transport_offset + bpf_ntohs(payload_length);

	/* Walk a bounded set of IPv6 extension headers before locating TCP/UDP. */
#pragma unroll
	for (i = 0; i < 6; i++) {
		if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
			break;
		if (protocol != 0 && protocol != 43 && protocol != 44 && protocol != 51 && protocol != 60)
			return TC_ACT_OK;
		header_type = protocol;
		if (bpf_skb_load_bytes(ctx, transport_offset, ext, sizeof(ext)) < 0)
			return TC_ACT_OK;
		if (header_type == 44) {
			__builtin_memcpy(&fragment, &ext[2], sizeof(fragment));
			if ((bpf_ntohs(fragment) & 0xfff8) != 0)
				return TC_ACT_OK;
			ext_len = 8;
		} else if (header_type == 51) {
			ext_len = ((__u16)ext[1] + 2) * 4;
		} else {
			ext_len = ((__u16)ext[1] + 1) * 8;
		}
		if (transport_offset + ext_len > payload_end)
			return TC_ACT_OK;
		transport_offset += ext_len;
		protocol = ext[0];
	}
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
		return TC_ACT_OK;
	if (bpf_skb_load_bytes(ctx, transport_offset, &source_port, sizeof(source_port)) < 0 ||
	    bpf_skb_load_bytes(ctx, transport_offset + 2, &destination_port, sizeof(destination_port)) < 0)
		return TC_ACT_OK;

	// TC runs in softirq context; process identity is not attributable to this packet.
	evt.pid = 0;
	evt.family = AF_INET6;
	evt.sport = bpf_ntohs(source_port);
	evt.dport = bpf_ntohs(destination_port);
	__builtin_memcpy(evt.saddr_v6, &ip[8], sizeof(evt.saddr_v6));
	__builtin_memcpy(evt.daddr_v6, &ip[24], sizeof(evt.daddr_v6));
	evt.protocol = protocol;
	evt.direction = direction;
	evt.state = 0;
	evt.netns = current_netns_inum();
	evt.cgroup_id = 0;
	evt.bytes = payload_end > transport_offset ? payload_end - transport_offset : 0;
	SUBMIT_EVENT(ctx, network_events, &evt);
	return TC_ACT_OK;
}

static __always_inline int emit_tc_packet(struct __sk_buff *ctx, __u8 direction)
{
	__u16 eth_proto, l3_offset;

	if (tc_l3_offset(ctx, &l3_offset, &eth_proto) < 0)
		return TC_ACT_OK;
	if (eth_proto == 0x0800)
		return emit_tc_ipv4(ctx, direction);
	if (eth_proto == 0x86dd)
		return emit_tc_ipv6(ctx, direction);
	return TC_ACT_OK;
}

SEC("classifier/elf_owl_tc_ingress")
int network_tc_ingress(struct __sk_buff *ctx)
{
	return emit_tc_packet(ctx, NET_DIR_INBOUND);
}

SEC("classifier/elf_owl_tc_egress")
int network_tc_egress(struct __sk_buff *ctx)
{
	return emit_tc_packet(ctx, NET_DIR_OUTBOUND);
}

char LICENSE[] SEC("license") = "GPL";
