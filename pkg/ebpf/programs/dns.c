// ANCHOR: DNS Monitor eBPF Program - Dec 27, 2025
// Kernel-native DNS query monitoring
// Captures DNS requests for CIS 4.6.4 controls (DNS exfiltration detection)

#include <uapi/linux/ptrace.h>
#include <uapi/linux/in.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/socket.h>
#include <linux/bpf.h>

#define DNS_HEADER_LEN 12
#define DNS_MAX_LABELS 10
#define DNS_MAX_LABEL_LEN 32

// Event structure matching enrichment.DNSQuery
struct dns_event {
    unsigned int pid;
    unsigned short query_type;  // A=1, AAAA=28, MX=15, TXT=16, etc.
    unsigned char response_code; // 0=NOERROR, 1=FORMERR, 2=SERVFAIL, etc.
    unsigned char query_allowed; // 1=allowed, 0=suspicious/blocked
    unsigned long cgroup_id;
    char query_name[256];        // Domain name being queried
    char server[16];             // DNS server IP (in IPv4 format)
};

// Perf buffer for sending events to userspace
BPF_PERF_OUTPUT(dns_events);

struct dns_recvfrom_args {
    void *buf;
    void *addr;
    unsigned int addr_len;
};

// ANCHOR: DNS recvfrom state tracking - Feature: response parsing - Mar 24, 2026
// Stores recvfrom buffers between sys_enter and sys_exit for payload inspection.
// Tracks recvfrom buffers so we can parse DNS responses on syscall exit.
BPF_HASH(dns_recvfrom_args_map, unsigned int, struct dns_recvfrom_args, 1024);

static __always_inline unsigned short dns_ntohs(unsigned short val) {
    return (val >> 8) | (val << 8);
}

static __always_inline int read_sockaddr(void *addr, unsigned short *port, unsigned char server[16]) {
    struct sockaddr sa = {};
    if (addr == 0) {
        return 0;
    }

    if (bpf_probe_read_user(&sa, sizeof(sa), addr) < 0) {
        return 0;
    }

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        if (bpf_probe_read_user(&sin, sizeof(sin), addr) < 0) {
            return 0;
        }
        *port = dns_ntohs(sin.sin_port);
        __builtin_memset(server, 0, 16);
        bpf_probe_read_user(server, sizeof(__u32), &sin.sin_addr);
        return AF_INET;
    }

    if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        if (bpf_probe_read_user(&sin6, sizeof(sin6), addr) < 0) {
            return 0;
        }
        *port = dns_ntohs(sin6.sin6_port);
        bpf_probe_read_user(server, 16, &sin6.sin6_addr);
        return AF_INET6;
    }

    return 0;
}

// ANCHOR: DNS payload parsing - Feature: query/rcode/ipv6/recv - Mar 24, 2026
// Parses DNS header + QNAME + QTYPE from user buffer with bounded loops.
static __always_inline void parse_dns_payload(void *buf, unsigned int len, struct dns_event *evt) {
    unsigned char header[DNS_HEADER_LEN] = {};
    int offset = DNS_HEADER_LEN;
    int out = 0;

    if (len < DNS_HEADER_LEN) {
        return;
    }

    if (bpf_probe_read_user(&header, sizeof(header), buf) < 0) {
        return;
    }

    evt->response_code = header[3] & 0x0F;

    // Skip if no questions
    if (header[4] == 0 && header[5] == 0) {
        return;
    }

#pragma unroll
    for (int i = 0; i < DNS_MAX_LABELS; i++) {
        unsigned char label_len = 0;
        if (offset >= len) {
            break;
        }
        if (bpf_probe_read_user(&label_len, sizeof(label_len), ((unsigned char *)buf) + offset) < 0) {
            break;
        }
        offset += 1;
        if (label_len == 0) {
            break;
        }

        if (label_len > DNS_MAX_LABEL_LEN) {
            label_len = DNS_MAX_LABEL_LEN;
        }

#pragma unroll
        for (int j = 0; j < DNS_MAX_LABEL_LEN; j++) {
            char c = 0;
            if (j >= label_len || offset + j >= len) {
                break;
            }
            if (bpf_probe_read_user(&c, sizeof(c), ((unsigned char *)buf) + offset + j) < 0) {
                break;
            }
            if (out < (int)sizeof(evt->query_name) - 1) {
                evt->query_name[out++] = c;
            }
        }

        if (out < (int)sizeof(evt->query_name) - 1) {
            evt->query_name[out++] = '.';
        }
        offset += label_len;
    }

    if (out > 0) {
        evt->query_name[out - 1] = 0;
    }

    if (offset + 2 <= len) {
        unsigned char qtype_bytes[2] = {};
        if (bpf_probe_read_user(&qtype_bytes, sizeof(qtype_bytes), ((unsigned char *)buf) + offset) == 0) {
            evt->query_type = ((unsigned short)qtype_bytes[0] << 8) | qtype_bytes[1];
        }
    }
}

// ANCHOR: DNS syscall tracepoints - Feature: send/recv payload capture - Mar 24, 2026
// Hooks sendto/recvfrom to capture DNS query and response payloads.
// Tracepoint: sys_enter_sendto (DNS queries/responses via UDP)
TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct dns_event evt = {};
    unsigned short port = 0;

    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.query_allowed = 1;
    evt.cgroup_id = bpf_get_current_cgroup_id();

    if (!read_sockaddr((void *)args->addr, &port, evt.server)) {
        return 0;
    }

    if (port != 53) {
        return 0;
    }

    parse_dns_payload((void *)args->buf, args->len, &evt);
    dns_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// Track recvfrom buffers on entry.
TRACEPOINT_PROBE(syscalls, sys_enter_recvfrom) {
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    struct dns_recvfrom_args args_state = {};

    args_state.buf = (void *)args->buf;
    args_state.addr = (void *)args->addr;
    args_state.addr_len = args->addr_len;

    dns_recvfrom_args_map.update(&pid, &args_state);
    return 0;
}

// Parse DNS responses on recvfrom exit.
TRACEPOINT_PROBE(syscalls, sys_exit_recvfrom) {
    unsigned int pid = bpf_get_current_pid_tgid() >> 32;
    struct dns_recvfrom_args *args_state = dns_recvfrom_args_map.lookup(&pid);
    struct dns_event evt = {};
    unsigned short port = 0;
    long ret = args->ret;

    if (!args_state) {
        return 0;
    }

    if (ret <= 0) {
        dns_recvfrom_args_map.delete(&pid);
        return 0;
    }

    evt.pid = pid;
    evt.query_allowed = 1;
    evt.cgroup_id = bpf_get_current_cgroup_id();

    if (!read_sockaddr(args_state->addr, &port, evt.server)) {
        dns_recvfrom_args_map.delete(&pid);
        return 0;
    }

    if (port != 53) {
        dns_recvfrom_args_map.delete(&pid);
        return 0;
    }

    parse_dns_payload(args_state->buf, ret, &evt);
    dns_events.perf_submit(args, &evt, sizeof(evt));
    dns_recvfrom_args_map.delete(&pid);
    return 0;
}
