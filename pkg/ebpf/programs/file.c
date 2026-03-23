// ANCHOR: File Monitor eBPF Program - Mar 23, 2026
// Captures file access intent via sys_enter_openat.

#include <linux/bpf.h>
#include <linux/fcntl.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct sys_enter_openat_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long dfd;
	const char *filename;
	long flags;
	long mode;
};

// Event layout must match pkg/ebpf/types.go: FileEvent.
struct file_event {
	__u32 pid;
	__u32 flags;
	__u8 operation;
	__u64 cgroup_id;
	char filename[256];
	char flags_str[32];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} file_events SEC(".maps");

#define FILE_OP_WRITE 1
#define FILE_OP_READ 2

static __always_inline __u8 classify_open(__u32 flags)
{
	if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) {
		return FILE_OP_WRITE;
	}
	return FILE_OP_READ;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int file_monitor(struct sys_enter_openat_ctx *ctx)
{
	struct file_event evt = {};
	__u32 flags = (__u32)ctx->flags;

	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.flags = flags;
	evt.operation = classify_open(flags);
	evt.cgroup_id = bpf_get_current_cgroup_id();

	if (ctx->filename) {
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), ctx->filename);
	}

	if (evt.operation == FILE_OP_WRITE) {
		__builtin_memcpy(evt.flags_str, "write", 6);
	} else {
		__builtin_memcpy(evt.flags_str, "read", 5);
	}

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
