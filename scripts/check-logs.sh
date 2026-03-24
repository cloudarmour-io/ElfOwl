#!/usr/bin/env bash
set -euo pipefail

VM_NAME="elf-owl-dev"
TYPE="all"
LINES="120"
VM_LOG_FILE="/var/log/elf-owl/agent.log"

usage() {
  cat <<USAGE
Usage: $(basename "$0") [options]

Options:
  --name <vm-name>    VM name (default: ${VM_NAME})
  --type <kind>       startup|monitors|events|violations|push|errors|all (default: ${TYPE})
  --lines <n>         Number of lines for fallback tail/all (default: ${LINES})
  -h, --help          Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) VM_NAME="$2"; shift 2 ;;
    --type) TYPE="$2"; shift 2 ;;
    --lines) LINES="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

multipass start "$VM_NAME" >/dev/null 2>&1 || true

PATTERN=""
case "$TYPE" in
  startup) PATTERN='elf-owl agent starting|configuration loaded|agent started successfully|health server listening|metrics server listening|failed to create agent|failed to start agent|shutdown signal received|agent stopped successfully' ;;
  monitors) PATTERN='monitor initialized|monitor started|loaded eBPF program|compliance watchers started|rule engine initialized' ;;
  events) PATTERN='process event sent|network event sent|dns event sent|file event sent|capability event sent|pod_spec_check|network_policy_check' ;;
  violations) PATTERN='CIS violation detected' ;;
  push) PATTERN='push: serialising events|push: succeeded|push attempt failed, retrying|failed to push events|dry-run: would push events' ;;
  errors) PATTERN='\"level\":\"(error|fatal)\"|failed|panic' ;;
  all) PATTERN='' ;;
  *) echo "Invalid --type: $TYPE"; usage; exit 1 ;;
esac

multipass exec "$VM_NAME" -- bash -lc "
  set -euo pipefail
  if ! sudo test -f '$VM_LOG_FILE'; then
    echo 'Log file not found: $VM_LOG_FILE'
    exit 1
  fi

  if [[ -n '$PATTERN' ]]; then
    sudo grep -E '$PATTERN' '$VM_LOG_FILE' | tail -n '$LINES' || true
  else
    sudo tail -n '$LINES' '$VM_LOG_FILE'
  fi
"
