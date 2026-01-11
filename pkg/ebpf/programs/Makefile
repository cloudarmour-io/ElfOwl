# ANCHOR: eBPF Program Build System - Dec 27, 2025
# Compiles eBPF C programs using Cilium/eBPF patterns
# Output: .o bytecode files for LoadPrograms() in pkg/ebpf/loader.go

CLANG ?= clang
LLC ?= llc
CFLAGS := -O2 -target bpf
OUTPUT := bin

# All eBPF programs
TARGETS := $(OUTPUT)/process.o $(OUTPUT)/network.o $(OUTPUT)/file.o \
           $(OUTPUT)/capability.o $(OUTPUT)/dns.o

.PHONY: all clean

all: $(OUTPUT) $(TARGETS)

# Create output directory
$(OUTPUT):
	mkdir -p $(OUTPUT)

# Compile eBPF C program to bytecode
$(OUTPUT)/%.o: %.c | $(OUTPUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT)

.DEFAULT_GOAL := all
