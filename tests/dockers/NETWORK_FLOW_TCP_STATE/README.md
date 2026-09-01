# Network Flow / TCP State Tracking Docker Test

Tests elf-owl's **bidirectional flow tracking and kernel TCP state transitions**
end-to-end against a real `--privileged` elf-owl container, a real `nginx:alpine`
target, and a mock webhook receiver — all driven by real TCP traffic on the host
kernel.

## What this tests

- elf-owl's `/health` and `/metrics` endpoints come up correctly
- `elf_owl_flows_created_total` and `elf_owl_flows_closed_total` both increase —
  proving flows are created **and** actually reach a terminal state, not just
  accumulating forever
- The mock webhook receiver captures `flow_summary` events whose `state` field
  is something other than `"new"` (e.g. `established`/`closing`/`closed`) — the
  direct regression check for:
  - the `tcp_state` kprobe wiring fix (kprobe section parsing, `LoadOptions.TCPState`
    plumbing, generic-reader bypass for the ringbuf-backed program)
  - the `ConnectionState` casing mismatch fix (`network.FlowStateFromName`)
  - the `tcp_connect` port=0 orphan-flow-key fix

## Why `--privileged` / real traffic (no mocks)

elf-owl attaches real kprobes (`tcp_set_state`) and tracepoints (`tcp_connect`,
`sock/inet_sock_set_state`) to the **host kernel** — there is no way to fake
this with mocks or a rootless/sandboxed container runtime. The elf-owl
container runs `--privileged` with the host's `/sys/kernel/btf` mounted
read-only so cilium/ebpf can resolve kernel BTF for CO-RE. This test must run
un-sandboxed on a real Linux host.

## Not covered by this suite

- **K8s enrichment** — the bare-metal enrichment backend is used instead
  (`kubernetes.in_cluster: false`), since this test focuses on flow tracking
  and TCP state, not K8s pod/RBAC context.
- **DNS/TLS/file/capability/process monitors** — disabled in the test config
  to keep the run focused and fast; only `network` and `tcp_state` are enabled.
- **Anomaly rule triggering** (DDoS flood, port scan, data exfiltration,
  tunnel detection) — these rules need sustained traffic volumes and time
  windows (e.g. "1000+ connections in 10 seconds") that aren't practical to
  drive in a short automated test. `pkg/rules/network_behavior.go` and
  `pkg/rules/engine_test.go` cover rule-matching logic directly.

## Files

- **`Dockerfile`** — minimal Alpine runtime with the static `elf-owl` binary
  (eBPF bytecode is embedded via `go:embed` at Go build time, so no separate
  `.o` files are shipped in the image)
- **`webhook_receiver.py`** — minimal Python HTTP server that logs every
  POSTed webhook batch (one JSON array per line) to `/data/events.log`
- **`test_flow_tracking_docker.sh`** — fully automated test script that:
  - Compiles `pkg/ebpf/programs/*.c` to `bin/*.o`
  - Builds a static `CGO_ENABLED=0` `elf-owl` binary (embeds the `.o` files)
  - Builds the Docker image and a Docker network
  - Starts the webhook receiver and an `nginx:alpine` target container
  - Starts elf-owl `--privileged` with a generated gateway-style config
  - Drives real `curl` traffic from a helper container to nginx
  - Verifies flow creation/closure via `/metrics` and real state transitions
    via the captured webhook events
  - Tears everything down (unless `--keep`)

## Running it

### Prerequisites

```bash
docker --version   # Docker daemon reachable, --privileged containers permitted
go version         # Go 1.19+
clang --version    # For compiling eBPF programs
make --version
curl --version
jq --version
```

Kernel BTF must be exposed at `/sys/kernel/btf/vmlinux` (standard on modern
kernels with `CONFIG_DEBUG_INFO_BTF=y`), and `pkg/ebpf/programs/vmlinux.h`
must already be generated:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/ebpf/programs/vmlinux.h
```

### Basic test

```bash
tests/dockers/NETWORK_FLOW_TCP_STATE/test_flow_tracking_docker.sh
```

### Options

```bash
# Keep containers running after test (for manual inspection)
tests/dockers/NETWORK_FLOW_TCP_STATE/test_flow_tracking_docker.sh --keep

# Verbose output for debugging
tests/dockers/NETWORK_FLOW_TCP_STATE/test_flow_tracking_docker.sh --verbose
```

Exit code is the number of failed checks (0 = all passed).

## Manual testing (for debugging)

### 1. Compile eBPF programs + build static binary

```bash
make -C pkg/ebpf/programs all
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
  -ldflags '-extldflags -static -s -w' \
  -o /tmp/flowtest-build/elf-owl ./cmd/elf-owl
```

### 2. Build the image

```bash
mkdir -p /tmp/flowtest-build
cp tests/dockers/NETWORK_FLOW_TCP_STATE/Dockerfile /tmp/flowtest-build/
cd /tmp/flowtest-build
docker build -t elf-owl:flowtest-manual .
```

### 3. Create network + start nginx + webhook receiver

```bash
docker network create elf-owl-flowtest-manual

docker run -d --name elf-owl-flowtest-manual-nginx \
  --network elf-owl-flowtest-manual nginx:alpine

mkdir -p /tmp/flowtest-build/webhook-data
docker run -d --name elf-owl-flowtest-manual-webhook \
  --network elf-owl-flowtest-manual \
  -v "$(pwd)/../../../tests/dockers/NETWORK_FLOW_TCP_STATE/webhook_receiver.py:/receiver.py:ro" \
  -v /tmp/flowtest-build/webhook-data:/data \
  python:3.12-alpine python3 /receiver.py
```

### 4. Start elf-owl (see `test_flow_tracking_docker.sh` for the full config
YAML it generates — copy it to `/tmp/flowtest-build/elf-owl.yaml`, pointing
`webhook.target_url` at `http://elf-owl-flowtest-manual-webhook:8888/events`)

```bash
docker run -d --name elf-owl-flowtest-manual-agent \
  --network elf-owl-flowtest-manual \
  --privileged \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /tmp/flowtest-build/elf-owl.yaml:/etc/elf-owl/elf-owl.yaml:ro \
  elf-owl:flowtest-manual
```

### 5. Generate traffic and inspect

```bash
docker run --rm --network elf-owl-flowtest-manual curlimages/curl \
  -s -o /dev/null http://elf-owl-flowtest-manual-nginx/

docker run --rm --network elf-owl-flowtest-manual curlimages/curl \
  -s http://elf-owl-flowtest-manual-agent:9090/metrics | grep elf_owl_flows

cat /tmp/flowtest-build/webhook-data/events.log | jq -s '[.[][] | select(.type == "flow_summary")]'
```

### 6. Manual cleanup

```bash
docker rm -f elf-owl-flowtest-manual-agent elf-owl-flowtest-manual-nginx elf-owl-flowtest-manual-webhook
docker network rm elf-owl-flowtest-manual
docker image rm elf-owl:flowtest-manual
```

## Troubleshooting

### Disk fills up on shared test hosts

The `network`/`tcp_state` eBPF programs attach to kprobes/tracepoints on the
**host kernel**, not just this test's own containers. On a shared host also
running other real traffic (other products' test suites, etc.), logging at
`debug` level captures every event system-wide, not just this test's -- one
run left running overnight grew a single container's log to 9.4GB with
`logging.level: debug`. This suite therefore defaults to `info`, and every
container the script starts is run with `--log-opt max-size=20m --log-opt
max-file=3` as a second safety net regardless of log level. Don't lower the
level back to `debug` and leave the container running (`--keep`) unattended
on a shared host.

### `/sys/kernel/btf/vmlinux missing or empty`

The host kernel doesn't expose BTF, or `bpftool` hasn't generated
`pkg/ebpf/programs/vmlinux.h` yet. See Prerequisites above.

### elf-owl health check fails

```bash
docker logs elf-owl-flowtest-agent
```

Look for `failed to load eBPF programs` (kprobe/tracepoint attach failure —
usually a missing capability or unavailable tracepoint on this kernel) or
`tcp state program set is nil` (would indicate a regression in the
`ebpf.LoadOptions.TCPState` wiring).

### All webhook events show `state: "new"`

This is the exact regression this test exists to catch. Check
`docker logs elf-owl-flowtest-agent | grep "flow tracked"` for
`state_source` values — if they're all empty/`UNKNOWN`, the
`sock/inet_sock_set_state` tracepoint may not be firing on this kernel.

## Performance expectations

- **Build time**: 30-90 seconds (eBPF compile + static Go build)
- **Container startup**: 5-10 seconds
- **Traffic generation + settle time**: ~15 seconds
- **Full cleanup**: 5-10 seconds

Total test runtime: ~2 minutes

## References

- `pkg/network/flow_tracker.go` — flow correlation and 4-state machine
- `pkg/network/tcp_states.go` — kernel TCP state → flow state mapping
- `pkg/ebpf/programs/tcp_state.c` — `tcp_set_state` kprobe
- `pkg/ebpf/programs/network.c` — `tcp_connect` / `sock/inet_sock_set_state` tracepoints
- `pkg/agent/agent.go` — `handleRuntimeEvent` flow correlation wiring
