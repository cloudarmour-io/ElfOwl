// ANCHOR: Process Monitor eBPF Program - Mar 23, 2026
// Captures process execution events via sys_enter_execve.

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct sys_enter_execve_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	const char *filename;
	const char *const *argv;
	const char *const *envp;
};

// Event layout must match pkg/ebpf/types.go: ProcessEvent.
struct process_event {
	__u32 pid;
	__u32 uid;
	__u32 gid;
	__u64 capabilities;
	char filename[256];
	char argv[256];
	__u64 cgroup_id;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} process_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct process_event);
} process_heap SEC(".maps");

static __always_inline void read_arg0(char *dst, __u32 dst_len, const char *const *argv)
{
	const char *arg0 = NULL;

	if (!argv) {
		return;
	}

	bpf_probe_read_user(&arg0, sizeof(arg0), argv);
	if (!arg0) {
		return;
	}

	bpf_probe_read_user_str(dst, dst_len, arg0);
}

SEC("tracepoint/syscalls/sys_enter_execve")
int process_monitor(struct sys_enter_execve_ctx *ctx)
{
	struct process_event *evt;
	__u32 key = 0;
	__u64 pid_tgid;
	__u64 uid_gid;

	evt = bpf_map_lookup_elem(&process_heap, &key);
	if (!evt) {
		return 0;
	}
	__builtin_memset(evt, 0, sizeof(*evt));

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();

	evt->pid = pid_tgid >> 32;
	evt->uid = (__u32)uid_gid;
	evt->gid = uid_gid >> 32;
	evt->cgroup_id = bpf_get_current_cgroup_id();
	evt->capabilities = 0;

	if (ctx->filename) {
		bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), ctx->filename);
	} else {
		bpf_get_current_comm(evt->filename, sizeof(evt->filename));
	}

	read_arg0(evt->argv, sizeof(evt->argv), ctx->argv);
	if (evt->argv[0] == '\0') {
		bpf_get_current_comm(evt->argv, sizeof(evt->argv));
	}

	bpf_perf_event_output(ctx, &process_events, BPF_F_CURRENT_CPU, evt, sizeof(*evt));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
