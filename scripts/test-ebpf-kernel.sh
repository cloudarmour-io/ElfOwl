#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"
SYNC=0
PULL=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --project-dir <vm-path>   VM project directory (default: ${VM_PROJECT_DIR})
  --sync                    Sync local source into VM before running tests
  --pull                    Pull VM-built .o files back into local repo
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    --sync) SYNC=1; shift ;;
    --pull) PULL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

BUILD_ARGS=(--name "$VM_NAME" --project-dir "$VM_PROJECT_DIR")
if [[ "$SYNC" -eq 1 ]]; then
  BUILD_ARGS+=(--sync)
fi
if [[ "$PULL" -eq 1 ]]; then
  BUILD_ARGS+=(--pull)
fi

"$SCRIPT_DIR/build-ebpf-vm.sh" "${BUILD_ARGS[@]}"

multipass start "$VM_NAME" >/dev/null 2>&1 || true

TS="$(date +%Y%m%d-%H%M%S)"
RESULTS_DIR="${VM_PROJECT_DIR}/.vm-test-results/${TS}-ebpf-kernel"
INTEG_LOG="${RESULTS_DIR}/ebpf-kernel.log"
UNIT_LOG="${RESULTS_DIR}/ebpf-unit.log"
UNIT_STATUS_FILE="${RESULTS_DIR}/ebpf-unit.status"
INTEG_STATUS_FILE="${RESULTS_DIR}/ebpf-kernel.status"

echo "[ebpf-test] Preparing VM results directory..."
multipass exec "$VM_NAME" -- bash -lc "mkdir -p '$RESULTS_DIR'"

echo "[ebpf-test] Running pkg/ebpf unit tests..."
set +e
multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  export PATH=/usr/local/go/bin:\$PATH
  cd '$VM_PROJECT_DIR'
  rm -f '$UNIT_STATUS_FILE'
  status=0
  GOCACHE=/tmp/elf-owl-gocache GOMODCACHE=/tmp/elf-owl-gomodcache go test -mod=mod -v ./pkg/ebpf | tee '$UNIT_LOG' || status=\$?
  echo \"\$status\" > '$UNIT_STATUS_FILE'
  exit 0
"
UNIT_STATUS="$(multipass exec "$VM_NAME" -- bash -lc "cat '$UNIT_STATUS_FILE' 2>/dev/null || echo 1")"

echo "[ebpf-test] Running root kernel integration tests..."
multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  cd '$VM_PROJECT_DIR'
  rm -f '$INTEG_STATUS_FILE'
  status=0
  sudo env PATH=/usr/local/go/bin:\$PATH ELFOWL_EBPF_INTEGRATION=1 GOCACHE=/tmp/elf-owl-gocache-root GOMODCACHE=/tmp/elf-owl-gomodcache-root \
    go test -mod=mod -tags=integration -v ./pkg/ebpf -run 'Test(Process|Network|File|Capability|DNS)ProgramEmitsEvents' | tee '$INTEG_LOG' || status=\$?
  echo \"\$status\" > '$INTEG_STATUS_FILE'
  exit 0
"
INTEG_STATUS="$(multipass exec "$VM_NAME" -- bash -lc "cat '$INTEG_STATUS_FILE' 2>/dev/null || echo 1")"
set -e

check_case() {
  local label="$1"
  local test_name="$2"
  if multipass exec "$VM_NAME" -- bash -lc "grep -q -- '--- PASS: ${test_name}' '$INTEG_LOG'"; then
    printf '%-14s %s\n' "$label" "PASS"
  else
    printf '%-14s %s\n' "$label" "FAIL"
  fi
}

echo
echo "=== Kernel Event Matrix ==="
check_case "process" "TestProcessProgramEmitsEvents"
check_case "network" "TestNetworkProgramEmitsEvents"
check_case "file" "TestFileProgramEmitsEvents"
check_case "capability" "TestCapabilityProgramEmitsEvents"
check_case "dns" "TestDNSProgramEmitsEvents"

echo
echo "=== Test Status ==="
echo "pkg/ebpf unit tests:      ${UNIT_STATUS}"
echo "kernel integration tests: ${INTEG_STATUS}"
echo "results dir:              ${RESULTS_DIR}"

if [[ "$UNIT_STATUS" != "0" || "$INTEG_STATUS" != "0" ]]; then
  exit 1
fi

echo "[ebpf-test] All eBPF tests passed."
