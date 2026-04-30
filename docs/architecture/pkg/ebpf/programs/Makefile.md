# `pkg/ebpf/programs/Makefile` — eBPF Build System

**Path:** `pkg/ebpf/programs/Makefile`
**Lines:** 37
**Purpose:** Compiles all six C eBPF programs to ELF `.o` objects in `bin/` using clang with BPF CO-RE flags.

---

## Variables

| Variable | Default | Description |
|---|---|---|
| `CLANG` | `clang` | C compiler (must support BPF target) |
| `TARGET_ARCH` | `x86` | BPF target architecture passed to `-D__TARGET_ARCH_$(TARGET_ARCH)` |
| `VMLINUX` | `vmlinux.h` | Path to generated BTF header |
| `BPF_INCLUDE` | `/usr/include/bpf` | libbpf include path |
| `CFLAGS` | (see below) | Compiler flags applied to all targets |

### CFLAGS

```
-g -O2 -target bpf
-D__TARGET_ARCH_x86
-I$(BPF_INCLUDE)
-I.
```

- `-g` — include DWARF/BTF debug info (required for CO-RE relocation)
- `-O2` — BPF verifier requires optimised code; loops must be bounded
- `-target bpf` — emit BPF bytecode ELF
- `-D__TARGET_ARCH_x86` — enables x86_64 syscall ID definitions in `common.h`
- `-I.` — resolves `vmlinux.h` and `common.h` from current directory

---

## Targets

| Target | Output | Source |
|---|---|---|
| `all` (default) | all six `.o` files | depends on all six program targets |
| `process` | `bin/process.o` | `process.c` |
| `network` | `bin/network.o` | `network.c` |
| `dns` | `bin/dns.o` | `dns.c` |
| `file` | `bin/file.o` | `file.c` |
| `capability` | `bin/capability.o` | `capability.c` |
| `tls` | `bin/tls.o` | `tls.c` |
| `vmlinux` | `vmlinux.h` | live kernel BTF |
| `clean` | — | removes `bin/*.o` |

### `vmlinux` target

```makefile
vmlinux:
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)
```

Requires `bpftool` and a running kernel with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`). The generated `vmlinux.h` is checked in; this target only needs re-running when targeting a different kernel version.

---

## Build Dependencies

```
clang (≥ 12)     — BPF target support, CO-RE
bpftool          — vmlinux.h generation only
linux-headers    — provides /sys/kernel/btf/vmlinux
libbpf headers   — /usr/include/bpf/bpf_helpers.h, bpf_core_read.h, bpf_tracing.h
```

The compiled `.o` files in `bin/` are committed to the repository so developers without a full eBPF toolchain can still build and test the Go agent.
