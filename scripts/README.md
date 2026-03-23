# VM Test Helper Scripts

Linux-only testing helpers using Multipass.

## Recommended Flow

1. `scripts/setup-vm.sh`
2. `scripts/start-vm.sh`
3. `scripts/test-ebpf-kernel.sh --sync --pull`
4. `scripts/test-events.sh --sync`
5. Optional full suite: `scripts/test-events.sh --full`
6. If you have Kubernetes access in VM: `scripts/start-agent.sh --kubeconfig /path/in/vm/config`
7. `scripts/check-state.sh`
8. `scripts/check-logs.sh --type startup`

## Scripts

- `setup-vm.sh`: create/provision VM, install base packages + Go, sync source into VM.
- `sync-vm-src.sh`: copy current repo snapshot into VM project directory.
- `start-vm.sh`: start VM and confirm source availability.
- `vm-exec.sh`: execute arbitrary command in VM (defaults to project dir).
- `build-ebpf-vm.sh`: compile all `pkg/ebpf/programs/*.c` inside VM and validate ELF artifacts (`--pull` copies them back locally).
- `test-ebpf-kernel.sh`: run VM unit tests + root kernel integration tests for process/network/file/capability/DNS event capture, with pass/fail matrix.
- `test-events.sh`: run event-path tests (`pkg/ebpf`, `pkg/rules` integration, and Kubernetes compliance event builders in `pkg/agent`) and print a pass/fail matrix (`--kernel` also runs root kernel eBPF integration checks).
- `start-agent.sh`: build/start agent in VM and fail fast with logs if startup fails.
- `stop-agent.sh`: stop running agent process.
- `check-state.sh`: process state + health + metrics + recent errors.
- `check-logs.sh`: filtered logs by category.
- `event-summary.sh`: count event/violation log lines (use debug level for event-sent counts).

## Important Notes

- The agent requires Kubernetes client access at startup. In plain VM mode, `start-agent.sh` will usually fail unless you pass `--kubeconfig` (or run in-cluster).
- `test-events.sh` is the primary verification path when Kubernetes is unavailable.
- Current known failing test in repository state: `pkg/rules` `TestIntegrationFileAccessViolation` (expects violation for `/etc` write, currently gets none).
