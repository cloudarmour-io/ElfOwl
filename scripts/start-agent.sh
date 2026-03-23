#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"
LOG_LEVEL="info"
REBUILD=0
SYNC=0
KUBECONFIG_PATH=""

VM_LOG_FILE="/var/log/elf-owl/agent.log"
VM_PID_FILE="/var/run/elf-owl/agent.pid"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>          VM name (default: ${VM_NAME})
  --project-dir <vm-path>   VM project directory (default: ${VM_PROJECT_DIR})
  --log-level <level>       debug|info|warn|error (default: ${LOG_LEVEL})
  --kubeconfig <vm-path>    KUBECONFIG path inside VM (required outside cluster)
  --sync                    Sync source into VM before build/start
  --rebuild                 Force rebuild of elf-owl binary
  -h, --help                Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    --log-level) LOG_LEVEL="$2"; shift 2 ;;
    --kubeconfig) KUBECONFIG_PATH="$2"; shift 2 ;;
    --sync) SYNC=1; shift ;;
    --rebuild) REBUILD=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if [[ "$SYNC" -eq 1 ]]; then
  "$SCRIPT_DIR/sync-vm-src.sh" --name "$VM_NAME" --project-dir "$VM_PROJECT_DIR"
fi

multipass start "$VM_NAME" >/dev/null 2>&1 || true

if [[ "$REBUILD" -eq 1 ]] || ! multipass exec "$VM_NAME" -- bash -lc "test -x '$VM_PROJECT_DIR/elf-owl'"; then
  echo "[agent] Building binary..."
  multipass exec "$VM_NAME" -- bash -lc "
    set -euo pipefail
    export PATH=/usr/local/go/bin:\$PATH
    cd '$VM_PROJECT_DIR'
    GOCACHE=/tmp/elf-owl-gocache GOMODCACHE=/tmp/elf-owl-gomodcache go build -mod=mod -o elf-owl ./cmd/elf-owl
  "
fi

KCFG_EXPORT=""
if [[ -n "$KUBECONFIG_PATH" ]]; then
  KCFG_EXPORT="export KUBECONFIG='$KUBECONFIG_PATH';"
fi

echo "[agent] Starting elf-owl..."
multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  sudo mkdir -p /var/log/elf-owl /var/run/elf-owl
  if sudo test -f '$VM_PID_FILE'; then
    old_pid=\$(sudo cat '$VM_PID_FILE' || true)
    if [[ -n \"\${old_pid}\" ]] && sudo kill -0 \"\${old_pid}\" 2>/dev/null; then
      sudo kill \"\${old_pid}\" || true
      sleep 1
    fi
  fi

  cd '$VM_PROJECT_DIR'
  sudo bash -lc '${KCFG_EXPORT} export OWL_LOG_LEVEL=${LOG_LEVEL}; nohup ./elf-owl > ${VM_LOG_FILE} 2>&1 & echo \$! > ${VM_PID_FILE}'
"

sleep 2
if ! multipass exec "$VM_NAME" -- bash -lc "pid=\$(sudo cat '$VM_PID_FILE' 2>/dev/null || true); [[ -n \"\$pid\" ]] && sudo kill -0 \"\$pid\" 2>/dev/null"; then
  echo "[agent] Agent exited early. Last logs:"
  multipass exec "$VM_NAME" -- bash -lc "sudo tail -n 80 '$VM_LOG_FILE'"
  echo
  echo "Hint: outside Kubernetes you usually need --kubeconfig <vm-path>"
  exit 1
fi

echo "[agent] Running."
echo "[agent] Logs: ${VM_LOG_FILE}"
