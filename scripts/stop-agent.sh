#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PID_FILE="/var/run/elf-owl/agent.pid"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [--name <vm-name>]
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

multipass start "$VM_NAME" >/dev/null 2>&1 || true

multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  if ! sudo test -f '$VM_PID_FILE'; then
    echo 'No PID file found. Agent is likely not running.'
    exit 0
  fi

  pid=\$(sudo cat '$VM_PID_FILE')
  if [[ -n \"\${pid}\" ]] && sudo kill -0 \"\${pid}\" 2>/dev/null; then
    sudo kill \"\${pid}\"
    echo \"Stopped elf-owl (PID \${pid}).\"
  else
    echo 'PID file exists but process is not running.'
  fi

  sudo rm -f '$VM_PID_FILE'
"
