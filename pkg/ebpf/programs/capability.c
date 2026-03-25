// ANCHOR: Capability Monitor eBPF Program - Mar 25, 2026
// Restores real capability-check telemetry via tracepoint/capability/cap_capable.

#include "common.h"

// Capability constants (include/uapi/linux/capability.h).
#define CAP_SYS_ADMIN 21
#define CAP_SYS_MODULE 16
#define CAP_SYS_BOOT 22
#define CAP_SYS_PTRACE 19

// This tracepoint format includes cap and cap_opt integer fields.
struct trace_event_raw_cap_capable {
	struct trace_entry ent;
	int cap;
	int cap_opt;
	char __data[0];
};

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

SEC("tracepoint/capability/cap_capable")
int capability_monitor(struct trace_event_raw_cap_capable *ctx)
{
	struct capability_event evt = {};
	__u32 cap = (__u32)ctx->cap;

	if (cap != CAP_SYS_ADMIN &&
	    cap != CAP_SYS_MODULE &&
	    cap != CAP_SYS_BOOT &&
	    cap != CAP_SYS_PTRACE) {
		return 0;
	}

	evt.pid = current_pid();
	evt.capability = cap;
	evt.check_type = 1;
	evt.cgroup_id = bpf_get_current_cgroup_id();
	// Best effort: retain process comm in syscall_name until explicit syscall
	// attribution is plumbed for this event shape.
	bpf_get_current_comm(evt.syscall_name, sizeof(evt.syscall_name));

	SUBMIT_EVENT(ctx, capability_events, &evt);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
