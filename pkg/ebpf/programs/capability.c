// ANCHOR: Capability Monitor eBPF Program - Mar 23, 2026
// Captures high-risk capability path via sys_enter_mount (CAP_SYS_ADMIN).

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

struct sys_enter_mount_ctx {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	long __syscall_nr;
	const char *dev_name;
	const char *dir_name;
	const char *type;
	unsigned long flags;
	const void *data;
};

// Capability constants (include/uapi/linux/capability.h).
#define CAP_SYS_ADMIN 21

// Event layout must match pkg/ebpf/types.go: CapabilityEvent.
struct capability_event {
	__u32 pid;
	__u32 capability;
	__u8 check_type;
	__u64 cgroup_id;
	char syscall_name[32];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} capability_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_mount")
int capability_monitor(struct sys_enter_mount_ctx *ctx)
{
	struct capability_event evt = {};

	evt.pid = bpf_get_current_pid_tgid() >> 32;
	evt.capability = CAP_SYS_ADMIN;
	evt.check_type = 1;
	evt.cgroup_id = bpf_get_current_cgroup_id();
	__builtin_memcpy(evt.syscall_name, "mount", 6);

	bpf_perf_event_output(ctx, &capability_events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
