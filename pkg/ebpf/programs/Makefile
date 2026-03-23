# ANCHOR: eBPF Program Build System - Dec 27, 2025 / Mar 23, 2026
# Builds libbpf-style tracepoint programs for embed + cilium/ebpf loading.

CLANG ?= clang
OUTPUT := bin
ARCH := $(shell uname -m)
ARCH_INCLUDE := /usr/include/$(ARCH)-linux-gnu
TARGET_ARCH ?= x86
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -I$(ARCH_INCLUDE)

TARGETS := $(OUTPUT)/process.o $(OUTPUT)/network.o $(OUTPUT)/file.o \
	$(OUTPUT)/capability.o $(OUTPUT)/dns.o

.PHONY: all clean

all: $(OUTPUT) $(TARGETS)

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/%.o: %.c | $(OUTPUT)
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OUTPUT)

.DEFAULT_GOAL := all
