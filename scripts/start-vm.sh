#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>        VM name (default: ${VM_NAME})
  --project-dir <vm-path> VM project directory (default: ${VM_PROJECT_DIR})
  -h, --help              Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass is required but not installed."
  exit 1
fi

if ! multipass info "$VM_NAME" >/dev/null 2>&1; then
  echo "VM '$VM_NAME' does not exist. Run scripts/setup-vm.sh first."
  exit 1
fi

echo "[start] Starting VM '$VM_NAME'..."
multipass start "$VM_NAME" >/dev/null 2>&1 || true

IP_ADDR="$(multipass info "$VM_NAME" | awk '/IPv4/{print $2; exit}')"
echo "[start] VM ready: $VM_NAME (${IP_ADDR:-no-ip})"

if multipass exec "$VM_NAME" -- bash -lc "test -r '$VM_PROJECT_DIR/go.mod'"; then
  echo "[start] Source present in VM: ${VM_PROJECT_DIR}"
else
  echo "[start] Source not found at ${VM_PROJECT_DIR}. Run scripts/sync-vm-src.sh"
fi
