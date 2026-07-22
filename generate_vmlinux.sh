#!/bin/bash
set -e

echo "=== ElfOwl eBPF Build Fix ==="

# Step 1: Check bpftool
echo -n "Checking bpftool... "
if ! command -v bpftool &> /dev/null; then
    echo "NOT FOUND"
    echo "Installing bpftool..."
    sudo apt-get update
    sudo apt-get install -y linux-tools-generic
else
    echo "OK"
    bpftool version
fi

# Step 2: Check kernel BTF
echo -n "Checking kernel BTF support... "
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "NOT FOUND"
    echo "ERROR: Kernel does not support BTF (CONFIG_DEBUG_INFO_BTF=y required)"
    echo "Your kernel: $(uname -r)"
    echo "You need to either:"
    echo "  1) Upgrade to kernel 5.10+ with BTF support"
    echo "  2) Recompile kernel with CONFIG_DEBUG_INFO_BTF=y"
    exit 1
else
    echo "OK"
fi

# Step 3: Check libbpf headers
echo -n "Checking libbpf headers... "
if [ ! -d /usr/include/bpf ]; then
    echo "NOT FOUND"
    echo "Installing libbpf-dev..."
    sudo apt-get install -y libbpf-dev
else
    echo "OK"
fi

# Step 4: Check linux headers
echo -n "Checking linux kernel headers... "
if [ ! -d /usr/include/linux ]; then
    echo "NOT FOUND"
    echo "Installing linux-headers..."
    sudo apt-get install -y linux-headers-$(uname -r)
else
    echo "OK"
fi

# Step 5: Generate vmlinux.h
echo "Generating vmlinux.h from kernel BTF..."
cd pkg/ebpf/programs
if [ -f vmlinux.h ]; then
    echo "vmlinux.h already exists, removing old version..."
    rm vmlinux.h
fi

bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
echo "Generated vmlinux.h ($(wc -l < vmlinux.h) lines)"

# Step 6: Build eBPF programs
echo "Building eBPF programs..."
make clean
make all

echo "=== Build Complete ==="
ls -lh bin/

