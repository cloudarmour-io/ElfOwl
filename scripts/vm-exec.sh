#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
VM_PROJECT_DIR="/home/ubuntu/work/owl-agent"
NO_CD=0

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options] -- <command>

Options:
  --name <vm-name>        VM name (default: ${VM_NAME})
  --project-dir <vm-path> VM project directory (default: ${VM_PROJECT_DIR})
  --no-cd                 Do not cd into project directory before command
  -h, --help              Show this help

Examples:
  $(basename "$0") -- go version
  $(basename "$0") --no-cd -- 'uname -a'
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --project-dir) VM_PROJECT_DIR="$2"; shift 2 ;;
    --no-cd) NO_CD=1; shift ;;
    --) shift; break ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done

if [[ $# -eq 0 ]]; then
  usage
  exit 1
fi

if ! command -v multipass >/dev/null 2>&1; then
  echo "multipass is required but not installed."
  exit 1
fi

if ! multipass info "$VM_NAME" >/dev/null 2>&1; then
  echo "VM '$VM_NAME' does not exist."
  exit 1
fi

multipass start "$VM_NAME" >/dev/null 2>&1 || true

CMD="$(printf '%q ' "$@")"
if [[ "$NO_CD" -eq 1 ]]; then
  multipass exec "$VM_NAME" -- bash -lc "$CMD"
else
  multipass exec "$VM_NAME" -- bash -lc "cd '$VM_PROJECT_DIR' && $CMD"
fi
