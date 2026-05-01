# `pkg/ebpf/programs/` — eBPF C Source Programs

**Purpose:** C source files for the eBPF programs compiled into `.o` ELF objects and embedded in the Go binary via `//go:embed`.

---

## Files

| File | Doc | Description |
|---|---|---|
| `Makefile` | [Makefile.md](./Makefile.md) | Build system — clang compilation + vmlinux.h generation |
| `common.h` | [common_h.md](./common_h.md) | Shared CO-RE helpers, syscall IDs, SUBMIT_EVENT macro |
| `process.c` | [process_c.md](./process_c.md) | Process execution events (`execve`/`execveat`) |
| `network.c` | [network_c.md](./network_c.md) | TCP connect, state change, UDP sendto events |
| `dns.c` | [dns_c.md](./dns_c.md) | DNS query events (stateful sendto→recvfrom tracking) |
| `file.c` | [file_c.md](./file_c.md) | File access events (openat, write, chmod, unlink) |
| `capability.c` | [capability_c.md](./capability_c.md) | Linux capability usage events |
| `tls.c` | [tls_c.md](./tls_c.md) | TLS ClientHello capture + JA3 fingerprint data |
| `bin/` | — | **Not documented** — compiled `.o` ELF outputs |
| `vmlinux.h` | — | **Not documented** — generated BTF header (bpftool output) |

---

## Build

```bash
# Full build (requires clang, bpftool, linux-headers)
make -C pkg/ebpf/programs

# Generate vmlinux.h only
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Outputs written to bin/
#   bin/process.o  bin/network.o  bin/dns.o
#   bin/file.o     bin/capability.o  bin/tls.o
```

---

## Architecture

```
vmlinux.h  (BTF header — CO-RE type information)
common.h   (shared helpers — included by most C files)
    │
    ├── process.c    →  bin/process.o
    ├── network.c    →  bin/network.o
    ├── dns.c        →  bin/dns.o        (does NOT include common.h)
    ├── file.c       →  bin/file.o       (does NOT include common.h)
    ├── capability.c →  bin/capability.o
    └── tls.c        →  bin/tls.o
```

`dns.c` and `file.c` use raw Linux headers (`<linux/bpf.h>`, `<linux/ptrace.h>`, etc.) instead of `common.h`.

---

## Tracepoints per Program

| Program | Tracepoints |
|---|---|
| `process.c` | `syscalls/sys_enter_execve`, `syscalls/sys_enter_execveat` |
| `network.c` | `tcp/tcp_connect`, `sock/inet_sock_set_state`, `syscalls/sys_enter_sendto` |
| `dns.c` | `syscalls/sys_enter_sendto`, `syscalls/sys_exit_recvfrom`, `syscalls/sys_enter_recvfrom` |
| `file.c` | `syscalls/sys_enter_openat`, `syscalls/sys_enter_write`, `syscalls/sys_enter_pwrite64`, `syscalls/sys_enter_chmod`, `syscalls/sys_enter_fchmodat`, `syscalls/sys_enter_unlinkat` |
| `capability.c` | `capability/cap_capable`, `raw_syscalls/sys_enter` |
| `tls.c` | `syscalls/sys_enter_write`, `syscalls/sys_enter_sendto`, `syscalls/sys_enter_writev`, `syscalls/sys_enter_sendmsg` |

---

## Key Design Constraints

- All programs use **CO-RE** (Compile Once Run Everywhere) via `vmlinux.h` — no kernel headers needed at runtime.
- **512-byte BPF stack limit** — `tls.c` uses a per-CPU array map (`tls_scratch`) as heap to store the 2048-byte TLS metadata buffer.
- **`__attribute__((packed))`** on `tls_client_hello_event` causes alignment differences vs Go structs — `DecodeTLSEvent()` in `pkg/ebpf/types.go` performs manual offset-based decoding.
- `capability.c` includes a `raw_syscalls/sys_enter` fallback for kernels where `capability/cap_capable` may not fire for `mount(2)`.
