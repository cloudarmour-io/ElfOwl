# ELF OWL Cheatsheet

Quick command reference for Multipass VM, Kubernetes status, agent control, and log/event checks.

## 1) VM Basics (Host Mac/Linux Shell)

```bash
# Start VM
scripts/start-vm.sh --name elf-owl-dev

# Enter VM shell
multipass shell elf-owl-dev

# Run one command in VM from host
scripts/vm-exec.sh --name elf-owl-dev --no-cd -- bash -lc 'uname -a'
```

## 2) Kubernetes Status (Inside VM Shell)

```bash
# k3s service state
sudo systemctl is-active k3s
sudo systemctl status k3s --no-pager -l

# cluster/node status
sudo k3s kubectl get nodes -o wide
sudo k3s kubectl get ns
sudo k3s kubectl get pods -A -o wide
```

## 3) Agent Lifecycle (Host Shell)

```bash
# Start agent (debug mode, kubeconfig from VM path)
scripts/start-agent.sh --name elf-owl-dev --sync --rebuild --log-level debug --kubeconfig /home/ubuntu/.kube/config

# Stop agent
scripts/stop-agent.sh --name elf-owl-dev

# Check runtime state + health + metrics
scripts/check-state.sh --name elf-owl-dev
```

## 4) Important Log Paths (Inside VM Shell)

```bash
# Main agent log
/var/log/elf-owl/agent.log

# PID file
/var/run/elf-owl/agent.pid
```

```bash
# View recent logs
sudo tail -n 200 /var/log/elf-owl/agent.log

# Follow logs live
sudo tail -F -n 150 /var/log/elf-owl/agent.log
```

## 5) Fast Event Summaries (Host Shell)

```bash
# High-level event counts
scripts/event-summary.sh --name elf-owl-dev

# Per-event sampled values
scripts/check-event-values.sh --name elf-owl-dev --lines 10

# Filtered logs via helper
scripts/check-logs.sh --name elf-owl-dev --type events --lines 300
scripts/check-logs.sh --name elf-owl-dev --type violations --lines 200
scripts/check-logs.sh --name elf-owl-dev --type errors --lines 100
```

## 6) Raw Log Filtering by Event Type (Inside VM Shell)

```bash
# Process events
sudo grep 'process event sent' /var/log/elf-owl/agent.log | tail -n 30

# Network events
sudo grep 'network event sent' /var/log/elf-owl/agent.log | tail -n 30

# DNS events
sudo grep 'dns event sent' /var/log/elf-owl/agent.log | tail -n 30

# File events
sudo grep 'file event sent' /var/log/elf-owl/agent.log | tail -n 30

# Capability events
sudo grep 'capability event sent' /var/log/elf-owl/agent.log | tail -n 30
```

## 7) Live Event Streams by Type (Inside VM Shell)

```bash
# Process only
sudo tail -F -n 200 /var/log/elf-owl/agent.log | grep --line-buffered 'process event sent'

# Network only
sudo tail -F -n 200 /var/log/elf-owl/agent.log | grep --line-buffered 'network event sent'

# DNS only
sudo tail -F -n 200 /var/log/elf-owl/agent.log | grep --line-buffered 'dns event sent'

# File only
sudo tail -F -n 200 /var/log/elf-owl/agent.log | grep --line-buffered 'file event sent'

# Capability only
sudo tail -F -n 200 /var/log/elf-owl/agent.log | grep --line-buffered 'capability event sent'
```

## 8) Trigger Test Activity (Host Shell)

```bash
# Generate process/network/dns/file/capability activity
scripts/generate-events.sh --name elf-owl-dev

# One-shot end-to-end: setup k8s, restart agent, generate events, print status/summaries
scripts/test-live-events.sh --name elf-owl-dev --sync --rebuild --sample-lines 5
```

## 9) Useful Maintenance

```bash
# Clear agent log file
scripts/vm-exec.sh --name elf-owl-dev --no-cd -- bash -lc 'sudo truncate -s 0 /var/log/elf-owl/agent.log'

# Show latest test result directories in VM
scripts/vm-exec.sh --name elf-owl-dev -- bash -lc 'ls -1dt .vm-test-results/* | head -n 10'

# Full kernel + integration validation
scripts/test-events.sh --name elf-owl-dev --sync --kernel
```

