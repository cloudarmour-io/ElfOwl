# ElfOwl Gateway Testing Guide

## Prerequisites

### System Requirements
- Linux kernel 5.10+ (for eBPF support)
- Go 1.21+
- LLVM/Clang 10+ (for eBPF compilation)
- libbpf-dev (libbpf development library)
- BTF support enabled (CONFIG_DEBUG_INFO_BTF=y in kernel)

### Required Tools
```bash
# Debian/Ubuntu
sudo apt-get install -y \
  clang llvm libelf-dev libelf1 libbpf-dev \
  linux-headers-$(uname -r) build-essential bpftool

# RHEL/CentOS
sudo dnf install -y \
  clang llvm elfutils-devel libbpf-devel \
  kernel-devel gcc bpftool
```

### Verify BTF Support
```bash
# Check if kernel has BTF support
uname -r
cat /boot/config-$(uname -r) | grep CONFIG_DEBUG_INFO_BTF

# Should output: CONFIG_DEBUG_INFO_BTF=y
```

## Building eBPF Programs

### Step 0: Build vvlinux.h

```bash
cd pkg/ebpf/programs
/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
wc -l vmlinux.h	#verify
```

### Step 1: Build eBPF Bytecode

The eBPF programs are located in `pkg/ebpf/programs/` and need to be compiled before running the agent.

```bash
# Navigate to eBPF programs directory
cd pkg/ebpf/programs

# Run make to compile all eBPF programs
make -C . all

# Verify compiled binaries exist
ls -la bin/
# Should show: network.o, process.o, dns.o, file.o, capability.o, tls.o
```

**If make fails**, check:
- LLVM/Clang version: `clang --version` (should be 10+)
- libbpf: `pkg-config --cflags libbpf`
- BTF: `bpftool btf list` (should show some BTF IDs)

### Step 2: Verify Compiled Artifacts

```bash
# Check eBPF object files are valid
file bin/network.o
# Should output: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV)

# Verify object file structure
llvm-objdump -d bin/network.o | head -20
```

### Step 3: Return to Project Root

```bash
cd ../../..  # Back to project root
```

## Building the Agent

```bash
# Build elf-owl binary
go build -o elf-owl cmd/elf-owl/main.go

# Verify binary was created
ls -lh elf-owl
file elf-owl
```

## Running the Agent

### Option 1: Gateway Profile (Recommended for Testing)

```bash
# Run with gateway configuration
sudo ./elf-owl --config config/profiles/elf-owl.gateway.yaml

# Expected output:
# {"level":"info","msg":"elf-owl agent starting",...}
# {"level":"info","msg":"kubernetes client skipped for enrichment backend","backend":"bare-metal"}
# {"level":"info","msg":"bare-metal enricher initialized",...}
# {"level":"info","msg":"agent started successfully",...}
```

**Note**: Agent requires root/CAP_BPF to load eBPF programs

### Option 2: Bare-Metal Profile (High-Performance)

```bash
sudo ./elf-owl --config config/profiles/elf-owl.baremetal.yaml
```

### Option 3: Kubernetes Profile (If in K8s)

```bash
sudo ./elf-owl --config config/profiles/elf-owl.kubernetes.yaml
```

## Testing Flow Tracking

### Manual Network Traffic Generation

In a separate terminal, generate network traffic to be captured:

```bash
# Generate DNS queries
nslookup google.com
nslookup github.com

# Generate TCP connections
curl -s https://example.com > /dev/null
ssh user@example.com

# Generate UDP traffic (if available)
ping -c 5 8.8.8.8
```

### Monitor Agent Logs

Watch the agent logs for flow tracking events:

```bash
# In agent terminal, look for:
# - Flow creation messages
# - Flow closure messages
# - Flow state transitions
# - Anomaly detection triggers
```

### Check Prometheus Metrics

```bash
# Query flow metrics (default: localhost:9090/metrics)
curl -s http://localhost:9090/metrics | grep "elf_owl_flows"

# Expected output:
# elf_owl_flows_active 5
# elf_owl_flows_created_total 23
# elf_owl_flows_closed_total{close_reason="fin"} 18
```

### Check Health Endpoint

```bash
# Query health status (default: localhost:9091/health)
curl -s http://localhost:9091/health | jq .

# Expected output:
# {
#   "status": "healthy",
#   "uptime": "2m30s",
#   "events_processed": 1234,
#   "monitors": {
#     "network": true,
#     "process": false,
#     ...
#   }
# }
```

## Unit Testing

### Test Flow Tracker
```bash
go test ./pkg/network/flow_tracker_test.go -v

# Expected: All tests pass (NewFlowTracker, AddOrUpdateFlow, CloseFlow, ExpireOldFlows)
```

### Test Rule Engine
```bash
go test ./pkg/rules/engine_test.go -v

# Expected: All tests pass (NewEngine, Match, Mode validation)
```

### Test Enrichment Backends
```bash
go test ./pkg/enrichment/backends/baremetal_enricher_test.go -v

# Expected: All tests pass (hostname resolution, process lookup, SELinux context)
```

### Test All Components
```bash
go test ./pkg/... -v

# Run all tests with coverage
go test -cover ./pkg/...
```

## Integration Testing

### Full Pipeline Test
```bash
# Run a test that simulates:
# 1. Network event capture (mocked)
# 2. Flow correlation
# 3. Rule matching
# 4. Enrichment
# 5. Webhook event generation

go test ./test/integration/... -v
```

### Webhook Event Verification
```bash
# Start a mock webhook receiver
python3 -m http.server 8888

# In another terminal, run agent and generate traffic
# Watch mock server receive flow_summary events
```

## Troubleshooting

### eBPF Compilation Fails

**Error**: `clang: command not found`
```bash
# Install LLVM/Clang
sudo apt-get install clang llvm
```

**Error**: `fatal error: 'bpf/libbpf.h' file not found`
```bash
# Install libbpf development files
sudo apt-get install libbpf-dev
```

**Error**: `CONFIG_DEBUG_INFO_BTF=y not found`
```bash
# Kernel doesn't have BTF support
# Either: 1) Upgrade kernel to 5.10+
#         2) Recompile kernel with BTF enabled
```

### Agent Won't Start with eBPF Error

**Error**: `failed to load eBPF programs: load network: get bytecode: failed to load network.o bytecode`
```bash
# Solution: Rebuild eBPF programs
cd pkg/ebpf/programs && make clean && make all && cd ../../..
```

**Error**: `permission denied` or `operation not permitted`
```bash
# Solution: Run with root or CAP_BPF
sudo ./elf-owl --config config/profiles/elf-owl.gateway.yaml

# Or use CAP_BPF capability:
sudo setcap cap_bpf,cap_perfmon+ep ./elf-owl
./elf-owl --config config/profiles/elf-owl.gateway.yaml
```

### No Network Events Captured

1. Verify eBPF programs loaded successfully: Check agent logs for "programs loaded"
2. Verify network interface is active: `ip link show`
3. Generate traffic: `curl https://example.com`
4. Check metrics: `curl http://localhost:9090/metrics | grep flows`

## Success Criteria

- ✅ eBPF programs compile without errors
- ✅ Agent binary builds successfully
- ✅ Agent starts with gateway profile
- ✅ Kubernetes client skipped for bare-metal backend
- ✅ Bare-metal enricher initializes
- ✅ Network events are captured and logged
- ✅ Flow tracking creates flows with proper state transitions
- ✅ Prometheus metrics are exported
- ✅ Health endpoint responds correctly
- ✅ Unit tests pass for all components
- ✅ No panics or crashes under normal operation

## Next Steps

1. **Phase 9 Testing**: Run comprehensive unit and integration tests
2. **Phase 10 Verification**: End-to-end deployment with real traffic
3. **Production Deployment**: Deploy to gateway, bare-metal, or VM environments
4. **Monitoring**: Set up Prometheus scraping and alerting for network anomalies
