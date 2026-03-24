// ANCHOR: DNS Monitor eBPF Program - Mar 23, 2026
// Captures DNS-oriented UDP sendto activity on port 53.

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

// Event layout must match pkg/ebpf/types.go: DNSEvent.
struct dns_event {
	__u32 pid;
	__u16 query_type;
	__u8 response_code;
	__u8 query_allowed;
	__u64 cgroup_id;
	char query_name[256];
	char server[16];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} dns_events SEC(".maps");

#ifndef AF_INET
#define AF_INET 2
#endif

static __always_inline int read_dns_destination(const struct sockaddr *uaddr, __u16 addr_len,
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

static __always_inline __u32 copy_label(const char *payload, __u64 payload_len, __u32 label_start,
					char *name_out, __u32 out_idx, __u8 label_len)
{
#pragma clang loop unroll(full)
	for (int i = 0; i < 63; i++) {
		char c = 0;

		if (i >= label_len || out_idx >= 255 || label_start + i >= payload_len) {
			break;
		}

		bpf_probe_read_user(&c, sizeof(c), payload + label_start + i);
		name_out[out_idx++] = c;
	}

	return out_idx;
}

// Parse a common "two labels + root" DNS question (e.g., example.com).
static __always_inline void parse_dns_question(const char *payload, __u64 payload_len,
					       char *name_out, __u16 *query_type)
{
	__u32 offset = 12;
	__u32 out_idx = 0;
	__u8 label_len = 0;
	__u16 qtype_be = 0;

	if (!payload || payload_len < 16) {
		return;
	}

	bpf_probe_read_user(&label_len, sizeof(label_len), payload + offset);
	if (label_len == 0 || label_len > 63 || offset + 1 + label_len > payload_len) {
		return;
	}
	out_idx = copy_label(payload, payload_len, offset + 1, name_out, out_idx, label_len);
	offset += 1 + label_len;

	bpf_probe_read_user(&label_len, sizeof(label_len), payload + offset);
	if (label_len > 0) {
		if (label_len > 63 || offset + 1 + label_len > payload_len) {
			return;
		}
		if (out_idx < 255) {
			name_out[out_idx++] = '.';
		}
		out_idx = copy_label(payload, payload_len, offset + 1, name_out, out_idx, label_len);
		offset += 1 + label_len;
	}

	if (offset >= payload_len) {
		return;
	}

	bpf_probe_read_user(&label_len, sizeof(label_len), payload + offset);
	if (label_len != 0) {
		return;
	}
	offset += 1;

	name_out[out_idx] = '\0';
	if (offset + 2 > payload_len) {
		return;
	}

	bpf_probe_read_user(&qtype_be, sizeof(qtype_be), payload + offset);
	*query_type = bpf_ntohs(qtype_be);
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int dns_monitor(struct sys_enter_sendto_ctx *ctx)
{
	__u16 family = 0;
	__u16 dport = 0;
	__u32 daddr = 0;
	struct dns_event evt = {};

	if (read_dns_destination(ctx->addr, (__u16)ctx->addr_len, &family, &dport, &daddr) < 0) {
		return 0;
	}
	if (family != AF_INET || dport != 53) {
		return 0;
	}

	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.query_type = 0;
	evt.response_code = 0;
	evt.query_allowed = 1;
	evt.cgroup_id = bpf_get_current_cgroup_id();
	__builtin_memcpy(evt.server, &daddr, sizeof(daddr));

	if (ctx->buff && ctx->len > 0) {
		__u16 query_type = 0;
		parse_dns_question(ctx->buff, (__u64)ctx->len, evt.query_name, &query_type);
		evt.query_type = query_type;
	}
	if (evt.query_name[0] == '\0') {
		bpf_get_current_comm(evt.query_name, sizeof(evt.query_name));
	}

	bpf_perf_event_output(ctx, &dns_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
