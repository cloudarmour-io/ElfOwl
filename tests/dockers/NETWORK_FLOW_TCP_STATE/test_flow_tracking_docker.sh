#!/bin/bash
#
# Automated Docker test for elf-owl's bidirectional flow tracking and kernel
# TCP state transitions. Runs a real --privileged elf-owl container attached
# to the host kernel's eBPF kprobes/tracepoints, alongside an nginx target
# container and a mock webhook receiver, and drives real TCP traffic between
# them to verify:
#
#   1. elf-owl's /health and /metrics endpoints come up and report activity
#   2. elf_owl_flows_created_total and elf_owl_flows_closed_total both
#      increase -- proving flows are created AND actually reach a terminal
#      state (not just accumulating forever at "new")
#   3. The webhook receiver captures at least one flow_summary event whose
#      "state" field is NOT "new" (e.g. "established"/"closing"/"closed") --
#      this is the direct regression check for the TCP state kprobe wiring
#      fix and the ConnectionState casing / tcp_connect orphan-key fix.
#
# This exercises real kprobes (tcp_set_state) and tracepoints (tcp_connect,
# sock/inet_sock_set_state) attached to the HOST kernel -- there is no way to
# mock this. The elf-owl container therefore runs --privileged with the
# host's /sys/kernel/btf mounted read-only. This test must run un-sandboxed
# on a real Linux host; it will not work in a restricted/rootless container
# runtime without equivalent capabilities.
#
# NOT covered by this suite: K8s enrichment (bare-metal backend is used
# instead), DNS/TLS/file/capability/process monitors (disabled to keep the
# test focused on network flow + TCP state), and anomaly rule triggering
# (DDoS/port-scan/exfil rules need sustained traffic patterns and time
# windows that aren't practical to drive in a short automated test).
#
# Usage:
#   tests/dockers/NETWORK_FLOW_TCP_STATE/test_flow_tracking_docker.sh [--keep] [--verbose]
#
#   --keep      Leave containers/network/image running after test
#   --verbose   Enable verbose output for debugging
#
# Requires: docker (privileged containers must be permitted), go, clang,
# make, curl, jq -- and must run as a user that can use --privileged Docker
# containers and read /sys/kernel/btf/vmlinux.

set -euo pipefail

# --- Config -----------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
KEEP=0
VERBOSE=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[FAIL]${NC} $1"; }
log_debug()   { if [ "$VERBOSE" -eq 1 ]; then echo -e "${BLUE}[DEBUG]${NC} $1" >&2; fi; }

while [ $# -gt 0 ]; do
    case "$1" in
        --keep)
            KEEP=1; shift ;;
        --verbose)
            VERBOSE=1; shift ;;
        -h|--help)
            sed -n '2,33p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *)
            log_error "Unknown argument: $1"; exit 1 ;;
    esac
done

IMAGE_TAG="elf-owl:flowtest-autotest"
NETWORK_NAME="elf-owl-flowtest-net"
WEBHOOK_CONTAINER="elf-owl-flowtest-webhook"
NGINX_CONTAINER="elf-owl-flowtest-nginx"
AGENT_CONTAINER="elf-owl-flowtest-agent"

# ANCHOR: Disk-backed workdir - Fix: RAM-backed /tmp tmpfs exhaustion on shared test hosts - Aug 14, 2026
# The static Go binary + go build cache + Docker build context for this test can total several
# hundred MB per run. On hosts where /tmp is a size-capped tmpfs (RAM-backed) shared with other
# products' test suites, repeated runs can exhaust it ("no space left on device") even though
# the real disk has plenty of room. Use a disk-backed directory under the repo instead.
mkdir -p "$REPO_ROOT/.test-tmp"
WORKDIR="$(mktemp -d "$REPO_ROOT/.test-tmp/flowtest.XXXXXX")"
FAILURES=0

pass() { log_success "$1"; }
fail() { log_error "$1"; FAILURES=$((FAILURES + 1)); }

cleanup() {
    if [ "$KEEP" -eq 1 ]; then
        log_info "Leaving containers/network/image up (--keep). To clean up later:"
        log_info "  docker rm -f $AGENT_CONTAINER $NGINX_CONTAINER $WEBHOOK_CONTAINER"
        log_info "  docker network rm $NETWORK_NAME"
        log_info "  Webhook event log: $WORKDIR/webhook-data/events.log"
        return
    fi
    log_info "Cleaning up containers and network..."
    docker rm -f "$AGENT_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$NGINX_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$WEBHOOK_CONTAINER" >/dev/null 2>&1 || true
    docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# curl_in_net <args...> -- runs curlimages/curl on the test network, sharing
# no host network/ports so container-to-container DNS names resolve.
curl_in_net() {
    docker run --rm --network "$NETWORK_NAME" curlimages/curl:latest "$@"
}

wait_for() {
    # wait_for <description> <timeout_seconds> <command...>
    local desc="$1" timeout="$2"; shift 2
    local waited=0
    while ! "$@" >/dev/null 2>&1; do
        if [ "$waited" -ge "$timeout" ]; then
            log_error "Timed out waiting for: $desc"
            return 1
        fi
        sleep 1
        waited=$((waited + 1))
    done
    return 0
}

# --- Preflight ---------------------------------------------------------------

command -v docker >/dev/null || { log_error "docker not found in PATH"; exit 1; }
command -v go     >/dev/null || { log_error "go not found in PATH"; exit 1; }
command -v clang  >/dev/null || { log_error "clang not found in PATH"; exit 1; }
command -v make   >/dev/null || { log_error "make not found in PATH"; exit 1; }
command -v curl   >/dev/null || { log_error "curl not found in PATH"; exit 1; }
command -v jq     >/dev/null || { log_error "jq not found in PATH"; exit 1; }
docker info >/dev/null 2>&1  || { log_error "docker daemon unreachable"; exit 1; }

if [ ! -s /sys/kernel/btf/vmlinux ]; then
    log_error "/sys/kernel/btf/vmlinux missing or empty -- host kernel must expose BTF"
    exit 1
fi

if [ ! -s "$REPO_ROOT/pkg/ebpf/programs/vmlinux.h" ]; then
    log_error "pkg/ebpf/programs/vmlinux.h missing or empty -- generate it first with:"
    log_error "  bpftool btf dump file /sys/kernel/btf/vmlinux format c > pkg/ebpf/programs/vmlinux.h"
    exit 1
fi

log_info "Repo root: $REPO_ROOT"
log_info "Work directory: $WORKDIR"
log_info "Verbose: $VERBOSE"

# --- Build eBPF bytecode + binary + image -----------------------------------

log_info "Compiling eBPF programs..."
make -C "$REPO_ROOT/pkg/ebpf/programs" all \
    || { log_error "Failed to compile eBPF programs"; exit 1; }

log_info "Building static elf-owl binary..."
cd "$REPO_ROOT"
CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags '-extldflags -static -s -w' \
    -o "$WORKDIR/elf-owl" ./cmd/elf-owl \
    || { log_error "Failed to build binary"; exit 1; }

log_info "Preparing Docker build context..."
cp "$SCRIPT_DIR/Dockerfile" "$WORKDIR/Dockerfile"

log_info "Building Docker image: $IMAGE_TAG"
docker build -t "$IMAGE_TAG" "$WORKDIR" \
    || { log_error "Failed to build Docker image"; exit 1; }

# --- Create network ----------------------------------------------------------

log_info "Creating Docker network: $NETWORK_NAME"
docker network create "$NETWORK_NAME" \
    || { log_error "Failed to create network"; exit 1; }

# --- Start webhook receiver --------------------------------------------------

log_info "Starting mock webhook receiver: $WEBHOOK_CONTAINER"
mkdir -p "$WORKDIR/webhook-data"
touch "$WORKDIR/webhook-data/events.log"
docker run -d \
    --name "$WEBHOOK_CONTAINER" \
    --network "$NETWORK_NAME" \
    --log-opt max-size=20m \
    --log-opt max-file=3 \
    -v "$SCRIPT_DIR/webhook_receiver.py:/receiver.py:ro" \
    -v "$WORKDIR/webhook-data:/data" \
    python:3.12-alpine python3 /receiver.py \
    || { log_error "Failed to start webhook receiver"; exit 1; }

log_info "Waiting for webhook receiver to be ready..."
wait_for "webhook receiver" 20 \
    curl_in_net -sf "http://${WEBHOOK_CONTAINER}:8888/" \
    || { docker logs "$WEBHOOK_CONTAINER"; exit 1; }
pass "Webhook receiver ready"

# --- Start nginx target -------------------------------------------------------

log_info "Starting nginx target container: $NGINX_CONTAINER"
docker run -d \
    --name "$NGINX_CONTAINER" \
    --network "$NETWORK_NAME" \
    --log-opt max-size=20m \
    --log-opt max-file=3 \
    nginx:alpine \
    || { log_error "Failed to start nginx"; exit 1; }

log_info "Waiting for nginx to be ready..."
wait_for "nginx" 20 \
    curl_in_net -sf "http://${NGINX_CONTAINER}/" \
    || { docker logs "$NGINX_CONTAINER"; exit 1; }
pass "nginx target ready"

# --- Create elf-owl configuration --------------------------------------------

log_info "Creating elf-owl configuration..."
CONFIG_FILE="$WORKDIR/elf-owl.yaml"
cat > "$CONFIG_FILE" <<EOF
agent:
  cluster_id: "flowtest"
  node_name: "flowtest-node"

  # ANCHOR: info-level logging - Bug: debug-level log grew to 9.4GB in one day - Aug 14, 2026
  # The network/tcp_state eBPF programs attach globally to the HOST kernel, not just this
  # test's own containers -- on a shared host running other real traffic, debug level logs
  # every event system-wide with no rotation, exhausting disk. info is sufficient for this
  # test's assertions (metrics + webhook events); the log-opts on the container below are a
  # second safety net regardless of level.
  logging:
    level: "info"
    format: "json"
    output: "stdout"

  ebpf:
    enabled: true
    kernel_btf_path: ""
    process:
      enabled: false
    network:
      enabled: true
      buffer_size: 8192
      timeout: 5s
    dns:
      enabled: false
    file:
      enabled: false
    capability:
      enabled: false
    tls:
      enabled: false
    tcp_state:
      enabled: true
      buffer_size: 4096
      timeout: 5s
    perf_buffer:
      enabled: true
      page_count: 256
      lost_handler: true
    ring_buffer:
      enabled: false
      size: 65536

  kubernetes:
    in_cluster: false

  rules:
    mode: "network-behavior"
    eval_timeout: 5s
    log_violations: true

  enrichment_backend:
    type: "bare-metal"
    bare_metal:
      reverse_dns: false
      process_lookup: false
      selinux_context: false

  evidence:
    signing:
      enabled: false
    encryption:
      enabled: false

  owl_api:
    endpoint: "http://unused.invalid"
    push:
      enabled: false
      dry_run: true

  metrics:
    enabled: true
    listen_address: ":9090"
    path: "/metrics"

  health:
    enabled: true
    listen_address: ":9091"
    path: "/health"

  webhook:
    enabled: true
    target_url: "http://${WEBHOOK_CONTAINER}:8888/events"
    batch_size: 10
    flush_interval: 2s
    timeout: 5s
EOF

# --- Start elf-owl ------------------------------------------------------------

log_info "Starting elf-owl container (privileged): $AGENT_CONTAINER"
docker run -d \
    --name "$AGENT_CONTAINER" \
    --network "$NETWORK_NAME" \
    --privileged \
    --log-opt max-size=20m \
    --log-opt max-file=3 \
    -v /sys/kernel/btf:/sys/kernel/btf:ro \
    -v /sys/kernel/debug:/sys/kernel/debug:ro \
    -v /sys/kernel/tracing:/sys/kernel/tracing:ro \
    -v "$CONFIG_FILE:/etc/elf-owl/elf-owl.yaml:ro" \
    "$IMAGE_TAG" \
    || { log_error "Failed to start elf-owl"; exit 1; }

elf_owl_health_ok() {
    curl_in_net -sf "http://${AGENT_CONTAINER}:9091/health" 2>/dev/null | jq -e '.status == "healthy"' >/dev/null 2>&1
}

log_info "Waiting for elf-owl to be ready..."
wait_for "elf-owl health" 30 elf_owl_health_ok \
    || { log_error "elf-owl failed to start"; docker logs "$AGENT_CONTAINER"; exit 1; }
pass "elf-owl ready"

# --- Generate real TCP traffic ------------------------------------------------

log_info "=== Traffic Generation Phase ==="

log_info "Generating repeated real TCP connections to nginx (connect -> data -> close)..."
for i in $(seq 1 10); do
    curl_in_net -s -o /dev/null "http://${NGINX_CONTAINER}/" || true
    log_debug "curl $i complete"
    sleep 0.3
done
pass "Generated 10 real TCP request/response cycles"

log_info "Waiting for flow state transitions, TTL/close handling, and webhook flush..."
sleep 8

# --- Verify via /metrics -------------------------------------------------------

log_info "=== Metrics Verification Phase ==="

METRICS=$(curl_in_net -s "http://${AGENT_CONTAINER}:9090/metrics")

FLOWS_CREATED=$(echo "$METRICS" | awk '/^elf_owl_flows_created_total / {print $2}')
FLOWS_CLOSED=$(echo "$METRICS" | awk '/^elf_owl_flows_closed_total/ {sum += $2} END {print sum+0}')

log_debug "elf_owl_flows_created_total = ${FLOWS_CREATED:-<missing>}"
log_debug "elf_owl_flows_closed_total (all reasons) = ${FLOWS_CLOSED:-<missing>}"

if [ -n "${FLOWS_CREATED:-}" ] && awk "BEGIN{exit !(${FLOWS_CREATED} > 0)}"; then
    pass "elf_owl_flows_created_total > 0 (${FLOWS_CREATED})"
else
    fail "elf_owl_flows_created_total missing or zero"
fi

if [ -n "${FLOWS_CLOSED:-}" ] && awk "BEGIN{exit !(${FLOWS_CLOSED} > 0)}"; then
    pass "elf_owl_flows_closed_total > 0 (${FLOWS_CLOSED}) -- flows reached a terminal state"
else
    fail "elf_owl_flows_closed_total missing or zero -- flows never left an active/new state"
fi

# --- Verify via webhook receiver -----------------------------------------------

log_info "=== Webhook Flow State Verification Phase ==="

EVENTS_LOG="$WORKDIR/webhook-data/events.log"
if [ ! -s "$EVENTS_LOG" ]; then
    fail "Webhook receiver captured no events at all"
else
    FLOW_SUMMARY_COUNT=$(jq -s '[.[][] | select(.type == "flow_summary")] | length' "$EVENTS_LOG" 2>/dev/null || echo 0)
    log_debug "flow_summary events captured: $FLOW_SUMMARY_COUNT"

    if [ "$FLOW_SUMMARY_COUNT" -gt 0 ]; then
        pass "Captured $FLOW_SUMMARY_COUNT flow_summary webhook event(s)"
    else
        fail "No flow_summary events captured by webhook receiver"
    fi

    NON_NEW_STATES=$(jq -s '[.[][] | select(.type == "flow_summary") | .flow_summary.state] | map(select(. != "new")) | unique' "$EVENTS_LOG" 2>/dev/null || echo '[]')
    NON_NEW_COUNT=$(echo "$NON_NEW_STATES" | jq 'length' 2>/dev/null || echo 0)

    if [ "$NON_NEW_COUNT" -gt 0 ]; then
        pass "flow_summary events show real state transitions beyond \"new\": $NON_NEW_STATES"
    else
        fail "All flow_summary events report state=\"new\" -- flows never transitioned (regression: TCP state tracking not working)"
    fi
fi

# --- Summary ----------------------------------------------------------------

echo ""
log_info "=== Test Summary ==="
if [ "$FAILURES" -eq 0 ]; then
    log_success "All tests passed!"
    echo ""
    exit 0
else
    log_error "$FAILURES test(s) failed"
    echo ""
    exit "$FAILURES"
fi
