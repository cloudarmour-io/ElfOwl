// ANCHOR: File Monitor eBPF Program - Mar 25, 2026
// Captures open, write, chmod, and unlink activity via syscall tracepoints.

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

struct sys_enter_write_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long fd;
	const char *buf;
	long count;
};

struct sys_enter_pwrite64_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long fd;
	const char *buf;
	long count;
	long pos;
};

struct sys_enter_chmod_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	const char *filename;
	long mode;
};

struct sys_enter_fchmodat_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long dfd;
	const char *filename;
	long mode;
};

struct sys_enter_unlinkat_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	long dfd;
	const char *pathname;
	long flag;
};

// Event layout must match pkg/ebpf/types.go: FileEvent.
struct file_event {
	__u32 pid;
	__u32 flags;
	__u32 mode;
	__u32 fd;
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
#define FILE_OP_CHMOD 3
#define FILE_OP_UNLINK 4

static __always_inline __u8 classify_open(__u32 flags)
{
	if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)) {
		return FILE_OP_WRITE;
	}
	return FILE_OP_READ;
}

static __always_inline void fill_common(struct file_event *evt, __u8 operation)
{
	__builtin_memset(evt, 0, sizeof(*evt));
	evt->pid = bpf_get_current_pid_tgid() >> 32;
	evt->operation = operation;
	evt->cgroup_id = bpf_get_current_cgroup_id();
}

static __always_inline void set_flags_str(struct file_event *evt)
{
	switch (evt->operation) {
	case FILE_OP_WRITE:
		__builtin_memcpy(evt->flags_str, "write", 6);
		break;
	case FILE_OP_READ:
		__builtin_memcpy(evt->flags_str, "read", 5);
		break;
	case FILE_OP_CHMOD:
		__builtin_memcpy(evt->flags_str, "chmod", 6);
		break;
	case FILE_OP_UNLINK:
		__builtin_memcpy(evt->flags_str, "unlink", 7);
		break;
	default:
		__builtin_memcpy(evt->flags_str, "unknown", 8);
		break;
	}
}

// ANCHOR: File syscall coverage - Feature: chmod/unlink/write tracing - Mar 25, 2026
// Emits file events from openat, write, pwrite64, chmod, fchmodat, and unlinkat.
SEC("tracepoint/syscalls/sys_enter_openat")
int file_monitor(struct sys_enter_openat_ctx *ctx)
{
	struct file_event evt = {};
	__u32 flags = (__u32)ctx->flags;
	__u8 operation = classify_open(flags);

	fill_common(&evt, operation);
	evt.flags = flags;
	evt.mode = (__u32)ctx->mode;
	evt.fd = (__u32)ctx->dfd;

	if (ctx->filename) {
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), ctx->filename);
	}

	set_flags_str(&evt);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int file_write_monitor(struct sys_enter_write_ctx *ctx)
{
	struct file_event evt = {};

	fill_common(&evt, FILE_OP_WRITE);
	evt.fd = (__u32)ctx->fd;
	set_flags_str(&evt);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int file_pwrite_monitor(struct sys_enter_pwrite64_ctx *ctx)
{
	struct file_event evt = {};

	fill_common(&evt, FILE_OP_WRITE);
	evt.fd = (__u32)ctx->fd;
	set_flags_str(&evt);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int file_chmod_monitor(struct sys_enter_chmod_ctx *ctx)
{
	struct file_event evt = {};

	fill_common(&evt, FILE_OP_CHMOD);
	evt.mode = (__u32)ctx->mode;

	if (ctx->filename) {
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), ctx->filename);
	}
	set_flags_str(&evt);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int file_fchmodat_monitor(struct sys_enter_fchmodat_ctx *ctx)
{
	struct file_event evt = {};

	fill_common(&evt, FILE_OP_CHMOD);
	evt.mode = (__u32)ctx->mode;
	evt.fd = (__u32)ctx->dfd;

	if (ctx->filename) {
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), ctx->filename);
	}
	set_flags_str(&evt);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int file_unlink_monitor(struct sys_enter_unlinkat_ctx *ctx)
{
	struct file_event evt = {};

	fill_common(&evt, FILE_OP_UNLINK);
	evt.flags = (__u32)ctx->flag;
	evt.fd = (__u32)ctx->dfd;

	if (ctx->pathname) {
		bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), ctx->pathname);
	}
	set_flags_str(&evt);

	bpf_perf_event_output(ctx, &file_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
