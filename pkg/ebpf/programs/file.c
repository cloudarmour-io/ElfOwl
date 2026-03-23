// ANCHOR: File Monitor eBPF Program - Dec 27, 2025
// Kernel-native file access monitoring
// Captures file write operations for CIS 4.5.5 controls

#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>

// Event structure matching enrichment.FileAccess
struct file_event {
    unsigned long cgroup_id;
    unsigned int pid;
    unsigned int flags;         // Open flags (O_WRONLY, O_RDWR, etc.)
    unsigned int mode;          // File mode (chmod/fchmodat/openat with O_CREAT)
    unsigned int fd;            // File descriptor (write/pwrite best-effort)
    unsigned char operation;    // write=1, read=2, chmod=3, unlink=4
    unsigned char sensitive;    // 1=path matches sensitive prefixes
    char filename[256];
    char flags_str[32];
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(file_events);

static __always_inline unsigned char is_sensitive_path(const char *path) {
    if (path[0] != '/') {
        return 0;
    }

    if (path[1] == 'e' && path[2] == 't' && path[3] == 'c' && path[4] == '/') {
        return 1;
    }
    if (path[1] == 'r' && path[2] == 'o' && path[3] == 'o' && path[4] == 't' && path[5] == '/') {
        return 1;
    }
    if (path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
        path[5] == 'r' && path[6] == 'u' && path[7] == 'n' && path[8] == '/') {
        return 1;
    }
    if (path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
        path[5] == 'l' && path[6] == 'i' && path[7] == 'b' && path[8] == '/' &&
        path[9] == 'k' && path[10] == 'u' && path[11] == 'b' && path[12] == 'e' &&
        path[13] == 'l' && path[14] == 'e' && path[15] == 't' && path[16] == '/') {
        return 1;
    }
    if (path[1] == 'e' && path[2] == 't' && path[3] == 'c' && path[4] == '/' &&
        path[5] == 'k' && path[6] == 'u' && path[7] == 'b' && path[8] == 'e' &&
        path[9] == 'r' && path[10] == 'n' && path[11] == 'e' && path[12] == 't' &&
        path[13] == 'e' && path[14] == 's' && path[15] == '/') {
        return 1;
    }
    if (path[1] == 'v' && path[2] == 'a' && path[3] == 'r' && path[4] == '/' &&
        path[5] == 'r' && path[6] == 'u' && path[7] == 'n' && path[8] == '/' &&
        path[9] == 's' && path[10] == 'e' && path[11] == 'c' && path[12] == 'r' &&
        path[13] == 'e' && path[14] == 't' && path[15] == 's' && path[16] == '/') {
        return 1;
    }

    return 0;
}

// ANCHOR: File openat extraction - Feature: flags/filename/mode/sensitive - Mar 24, 2026
// Captures filename, open flags, and mode (O_CREAT) for write intent classification.
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct file_event evt = {};

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;

    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), (void *)args->filename);
    evt.flags = args->flags;
    evt.mode = args->mode;
    evt.sensitive = is_sensitive_path(evt.filename);

    if ((evt.flags & O_WRONLY) || (evt.flags & O_RDWR)) {
        evt.operation = 1;  // write
    } else {
        evt.operation = 2;  // read
    }

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// ANCHOR: File syscall expansion - Feature: write/chmod/unlink coverage - Mar 24, 2026
// Adds write, chmod, and unlink tracing for richer file activity signals.
TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct file_event evt = {};

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.operation = 1;  // write
    evt.fd = args->fd;

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_pwrite64) {
    struct file_event evt = {};

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.operation = 1;  // write
    evt.fd = args->fd;

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
    struct file_event evt = {};

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.operation = 3;  // chmod
    evt.mode = args->mode;
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), (void *)args->filename);
    evt.sensitive = is_sensitive_path(evt.filename);

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
    struct file_event evt = {};

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.operation = 3;  // chmod
    evt.mode = args->mode;
    evt.fd = args->dfd;
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), (void *)args->filename);
    evt.sensitive = is_sensitive_path(evt.filename);

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    struct file_event evt = {};

    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.operation = 4;  // unlink
    evt.fd = args->dfd;
    bpf_probe_read_user_str(&evt.filename, sizeof(evt.filename), (void *)args->pathname);
    evt.sensitive = is_sensitive_path(evt.filename);

    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
