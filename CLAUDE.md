# elf-owl Development Guide for Claude

**Version:** 2.0.0
**Date:** July 18, 2026
**Project:** elf-owl - Network-Behavior-Centric Gateway/Firewall Monitoring Platform with Optional Kubernetes Compliance
**Status:** Phase 8 Complete - Core Architecture Operational (18/25 tasks)

---

## Overview

elf-owl is a **network-behavior-centric monitoring platform** optimized for firewall, gateway, and enterprise network deployments. It provides:

- **Bidirectional flow tracking** with conntrack-style correlation and 4-state machine
- **Network anomaly detection** (DDoS, port scanning, data exfiltration, tunneling)
- **Pluggable enrichment backends** (bare-metal, Kubernetes, extensible to cloud)
- **Dual-mode rule engine** (network-behavior OR compliance OR both)
- **Environment-agnostic architecture** (Gateway, Bare-Metal, VM, K8s deployments)

The platform evolved from a Kubernetes-centric compliance agent to a general-purpose network behavior monitor with optional CIS Kubernetes v1.8 compliance validation.

---

## Table of Contents

1. [Network-Behavior-Centric Design](#network-behavior-centric-design)
2. [Deployment Modes](#deployment-modes)
3. [Flow Tracking Architecture](#flow-tracking-architecture)
4. [Code Changes Workflow](#code-changes-workflow)
5. [Anchor Comments Requirement](#anchor-comments-requirement)
6. [Git Commit Message Types](#git-commit-message-types)
7. [Code Review Standards](#code-review-standards)
8. [Project Structure & Key Files](#project-structure--key-files)
9. [Development Workflow](#development-workflow)
10. [Important Constraints](#important-constraints)
11. [Common Development Tasks](#common-development-tasks)

---

## Network-Behavior-Centric Design

### Core Principles

1. **Environment-Agnostic Core**: Network flow tracking and anomaly detection work across any deployment (gateway, bare-metal, VM, Kubernetes)
2. **Pluggable Enrichment**: Backend-specific context (K8s pod, host process, cloud metadata) is optional and swappable
3. **Bidirectional Flow Correlation**: Events are correlated into bidirectional flows using canonical tuple matching (conntrack-style)
4. **Dual-Mode Rules**: Support network-behavior detection OR compliance checking OR both simultaneously
5. **Flow State Machine**: Simplified 4-state machine (NEW → ESTABLISHED → CLOSING → CLOSED) for firewall operators

### Key Components

- **Flow Tracker** (`pkg/network/flow_tracker.go`): Bidirectional flow correlation with TTL-based expiry and memory limits
- **Enrichment Interface** (`pkg/enrichment/enricher.go`): Backend-agnostic interface for context injection
- **Enrichment Backends** (`pkg/enrichment/backends/`):
  - `baremetal_enricher.go`: Hostname, process, OS context via /proc and reverse DNS
  - `k8s_enricher.go`: Pod, service account, RBAC, network policy context
- **Dual-Mode Rule Engine** (`pkg/rules/engine.go`): Mode-aware matching (network-behavior, compliance, dual)
- **Network Behavior Rules** (`pkg/rules/network_behavior.go`): 5 anomaly detection rules (DDoS, port scan, exfil, tunnel, connection retry)
- **Compliance Rules** (`pkg/rules/cis_compliance.go`): 48 CIS Kubernetes v1.8 controls (moved from hardcoded)

---

## Deployment Modes

### Gateway Profile (`config/profiles/elf-owl.gateway.yaml`)
- **Rule Mode**: network-behavior (anomaly detection only)
- **Enrichment**: bare-metal (hostname, process, OS context)
- **Resource Profile**: Gateway-optimized (16KB network buffer, minimal overhead)
- **Use Case**: Firewalls, network gateways, SOHO devices

### Bare-Metal Profile (`config/profiles/elf-owl.baremetal.yaml`)
- **Rule Mode**: network-behavior (anomaly detection only)
- **Enrichment**: bare-metal (hostname, process, SELinux context)
- **Resource Profile**: High-performance (32KB network buffer, 1K perf pages, extended caches)
- **Use Case**: Dedicated bare-metal monitoring servers

### VM Profile (`config/profiles/elf-owl.vm.yaml`)
- **Rule Mode**: network-behavior (anomaly detection only)
- **Enrichment**: bare-metal (minimal: no reverse DNS or process lookup)
- **Resource Profile**: Minimal (4KB network buffer, 64 perf pages, short caches)
- **Use Case**: Resource-constrained VMs and containers

### Kubernetes Profile (`config/profiles/elf-owl.kubernetes.yaml`)
- **Rule Mode**: compliance (CIS Kubernetes v1.8 controls)
- **Enrichment**: kubernetes (full pod, RBAC, network policy context)
- **Resource Profile**: Moderate (16KB buffers, 512 perf pages, K8s API integration)
- **Use Case**: K8s DaemonSet deployments, compliance audits

### Comprehensive Profile (`config/profiles/elf-owl.comprehensive.yaml`)
- **Rule Mode**: dual (both network-behavior AND compliance)
- **Enrichment**: kubernetes (full context for both rule sets)
- **Resource Profile**: Maximum (32KB buffers, 2K perf pages, all monitors enabled)
- **Use Case**: High-security environments requiring defense-in-depth

---

## Flow Tracking Architecture

### Flow State Machine (4 States)

```
NEW
  ↓
ESTABLISHED
  ↓
CLOSING
  ↓
CLOSED
```

- **NEW**: SYN_SENT, SYN_RECV (pending connection establishment)
- **ESTABLISHED**: Bidirectional data flow (connection fully established)
- **CLOSING**: FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT, LAST_ACK (graceful shutdown)
- **CLOSED**: Fully terminated (can be removed from tracking)

### Flow Key (Bidirectional Tuple)

```go
type FlowKey struct {
    IP1      string // Canonical: min(src, dst)
    Port1    uint16 // Port for IP1
    IP2      string // Canonical: max(src, dst)
    Port2    uint16 // Port for IP2
    Protocol string // tcp, udp, icmp, etc.
    NetnsID  uint32 // Network namespace
}
```

Canonical ordering ensures `src→dst` and `dst→src` events map to the same flow.

### Flow Tracking Configuration

- **ActiveTTL**: Time before idle flow is expired (default: 30min gateway, 60min LB, 10min VM)
- **MaxActiveFlows**: Maximum concurrent tracked flows (default: 500k)
- **MemoryLimitMB**: Memory budget for flow tracking (default: 256MB)
- **Eviction Policy**: LRU (least recently used) when limits exceeded

### Metrics Exported

- `elf_owl_flows_active`: Current active flow count
- `elf_owl_flows_created_total`: Total flows created
- `elf_owl_flows_closed_total`: Closed flows by reason (fin, reset, timeout, evicted)
- `elf_owl_flow_bytes_transferred`: Bytes per flow histogram
- `elf_owl_anomalies_detected_total`: Network anomalies detected
- `elf_owl_ddos_floods_detected_total`: DDoS flood events
- `elf_owl_port_scans_detected_total`: Port scan events
- `elf_owl_data_exfiltration_suspected_total`: Data exfiltration suspicions
- `elf_owl_tunnels_detected_total`: Long-lived tunnel detections

---

## Code Changes Workflow

### Plan-First Approach (MANDATORY)

Claude **MUST** follow this workflow for ALL code changes:

1. **Understand the Request** - Read and comprehend the user's request
2. **Explore Codebase** - Use Glob, Grep, and Read tools to understand affected code
3. **Create a Plan** - Document the proposed changes with:
   - Files to modify
   - Specific line numbers and sections
   - Rationale for each change
   - Potential side effects or impacts
4. **Present Plan to User** - Show the plan and wait for explicit approval
5. **Implement After Approval** - Only make code changes after user explicitly approves
6. **Test and Verify** - Run tests and verify changes work correctly

**DO NOT make code changes without an approved plan.**

### Plan Presentation Template

When presenting a plan, use this structure:

```
## Plan: [Feature/Fix Name]

### Overview
[One sentence description of what will be done]

### Files to Modify

1. File: `path/to/file.go`
   - Lines: XX-YY
   - Change: [What will be modified]
   - Reason: [Why this change is necessary]
   - Anchor Comment: [Proposed ANCHOR comment]

2. File: `path/to/file2.go`
   - Lines: AA-BB
   - Change: [What will be modified]
   - Reason: [Why this change is necessary]
   - Anchor Comment: [Proposed ANCHOR comment]

### Git Commits

1. `type: message` - Commit 1 description
2. `type: message` - Commit 2 description

### Testing

- [How changes will be tested]
- [What could go wrong]
- [How to verify success]

### Approval

Please review and approve before implementation begins.
```

---

## Anchor Comments Requirement

### Why Anchor Comments?

Anchor comments serve as documentation and traceability markers in the codebase. They help future developers understand:
- What a code section does
- Why it was implemented that way
- What bug or issue it addresses
- When it was added

### Anchor Comment Format

All new code and modified code sections **MUST** include anchor comments:

```go
// ANCHOR: [PURPOSE] - [BUG/ISSUE/FEATURE] - [DATE]
// [Detailed explanation of the approach and rationale]
```

### Anchor Comment Examples

**Example 1: Bug Fix**
```go
// ANCHOR: NetworkPolicy label selector matching - Bug #2: MatchExpressions ignored - Dec 20, 2025
// Implemented full label selector evaluation including MatchExpressions operators (In, NotIn, Exists, DoesNotExist).
// Previous code only checked MatchLabels, causing false positives in CIS 4.6.5 network isolation checks.
func (c *Client) selectorMatches(selector *metav1.LabelSelector, labels map[string]string) bool {
	// Implementation...
}
```

**Example 2: New Feature**
```go
// ANCHOR: Rule loading from YAML file - Feature: Configurable CIS controls - Jan 8, 2026
// Allows operators to load CIS rules from external YAML files instead of hardcoded mappings.
// Supports dynamic rule updates without code changes or recompilation.
func LoadRulesFromFile(filePath string) ([]*Rule, error) {
	// Implementation...
}
```

**Example 3: Complex Logic Section**
```go
// ANCHOR: RBAC privilege level calculation - Enhancement: Multi-level privilege detection - Dec 21, 2025
// Calculates privilege levels across RoleBindings and ClusterRoleBindings using permission counting.
// Levels: 0=restricted (0 permissions), 1=standard (1-10), 2=elevated (11-100), 3=admin (100+).
func (c *Client) GetRBACLevel(ctx context.Context, serviceAccount, namespace string) (int, error) {
	// Implementation...
}
```

### Where to Add Anchor Comments

**DO add anchors for:**
- New functions and methods
- Critical bug fixes
- Complex logic sections
- Integration points with other systems
- Configuration/flag handling
- Error handling paths
- Security-sensitive code
- Performance optimizations

**DO NOT add anchors for:**
- Simple variable assignments
- Loop bodies in straightforward iteration
- Standard library usage without customization
- Self-explanatory code (e.g., `count := count + 1`)
- Comments that already exist and are clear

---

## Git Commit Message Types

### Message Format

Use conventional commit message format:

```
type: description

[Optional detailed explanation]
```

### Commit Types

| Type | Usage | Example |
|------|-------|---------|
| **feat** | Adding a New Feature | `feat: implement rule loading from YAML file` |
| **fix** | Bug Fixes | `fix: correct NetworkPolicy selector matching for MatchExpressions` |
| **chore** | Maintenance & Non-Code Updates | `chore: update Go dependencies` |
| **style** | Code Formatting (No Logic Changes) | `style: format enricher.go to match linter` |
| **refactor** | Code Improvement Without Changing Functionality | `refactor: extract label matching to helper function` |
| **docs** | Documentation Updates | `docs: add remediation examples for CIS_4.5.1` |
| **perf** | Performance Improvements | `perf: optimize pod lookup with concurrent metadata cache` |
| **test** | Adding or Updating Tests | `test: add integration tests for enrichment pipeline` |
| **ci** | Changes to CI/CD Configuration | `ci: add golangci-lint configuration` |

### Commit Message Guidelines

- **First line:** Short, imperative mood, present tense (50 chars max)
- **Blank line:** Separate subject from body
- **Body:** Explain **why** not **what** (lines 72 chars max)
- **References:** Include issue/bug numbers when applicable
- **Co-author:** Include Claude as co-author

### Example Good Commit

```
fix: correct pod lookup optimization causing cache misses

The container ID extraction was using partial cgroup paths that didn't
consistently match pod UIDs in the cache. This caused 30% cache miss
rate for subsequent enrichment lookups.

Changed to extract full pod UID from cgroup hierarchy:
  /kubepods.slice/kubepods-pod{UID}.slice → {UID}

This fixes Bug #5 where network policies weren't being attached to
enriched events due to missing pod metadata.

Fixes: #74

```

---

## Code Review Standards

### Before Making Changes

- [ ] Plan created and approved by user
- [ ] Anchor comments identified in plan
- [ ] Commit messages planned
- [ ] Potential impacts understood
- [ ] Existing tests reviewed

### During Implementation

- [ ] Anchor comments added to code
- [ ] Changes minimal and targeted
- [ ] No over-engineering
- [ ] Error handling complete
- [ ] Logging included (if relevant)
- [ ] Code follows project style

### After Implementation

- [ ] All modified files reviewed
- [ ] Anchor comments verified present
- [ ] Commit message matches type guidelines
- [ ] Tests pass (if applicable)
- [ ] No security vulnerabilities introduced
- [ ] No performance regressions

---

## Project Structure & Key Files

### Core Directories (Updated for Network-Behavior Architecture)

```
elf-owl/
├── cmd/elf-owl/                 # Agent entry point
│   └── main.go                  # Bootstrap code
│
├── pkg/
│   ├── agent/                   # Core agent orchestration
│   │   ├── agent.go             # Main agent loop with backend selection
│   │   ├── config.go            # Configuration types (RulesConfig.Mode, EnrichmentBackendConfig)
│   │   └── webhook.go           # Webhook pusher with FlowSummaryEvent support
│   │
│   ├── network/                 # Network flow tracking (NEW)
│   │   ├── flow_tracker.go      # Bidirectional flow correlation (327 LOC)
│   │   │   └── 4-state machine, TTL-based expiry, LRU eviction, flow metrics
│   │   └── flow_tracker_test.go # Flow tracker unit tests
│   │
│   ├── enrichment/              # Pluggable event enrichment backends
│   │   ├── enricher.go          # Enricher interface (backend-agnostic)
│   │   ├── types.go             # Data structures (NetworkContext with flow fields)
│   │   ├── k8s_enricher.go      # Kubernetes enrichment implementation
│   │   └── backends/            # Backend implementations (NEW)
│   │       ├── baremetal_enricher.go    # Bare-metal enrichment (hostname, process, SELinux)
│   │       ├── baremetal_config.go      # Bare-metal configuration
│   │       ├── baremetal_enricher_test.go
│   │       ├── k8s_enricher.go   # K8s backend wrapper
│   │       ├── k8s_config.go     # K8s backend configuration
│   │       └── k8s_enricher_test.go
│   │
│   ├── rules/                   # Dual-mode rule engine
│   │   ├── engine.go            # Rule matching engine (mode-aware)
│   │   ├── cis_compliance.go    # 48 CIS Kubernetes v1.8 controls (NEW, moved from cis_mappings)
│   │   ├── network_behavior.go  # 5 network behavior anomaly detection rules (NEW)
│   │   ├── loader.go            # Mode-aware rule loading (LoadNetworkBehaviorRules, LoadComplianceRules, LoadDualModeRules)
│   │   ├── engine_test.go       # Rule engine tests
│   │   ├── loader_test.go       # Loader tests
│   │   └── integration_test.go  # Integration tests
│   │
│   ├── kubernetes/              # K8s metadata client (legacy, now via enrichment backend)
│   │   ├── client.go            # K8s API client (600+ LOC)
│   │   └── cache.go             # Metadata cache (200+ LOC)
│   │
│   ├── evidence/                # Evidence processing
│   │   ├── signer.go            # HMAC-SHA256 signing
│   │   ├── cipher.go            # AES-256-GCM encryption
│   │   └── buffer.go            # Event buffering
│   │
│   ├── api/                     # Owl SaaS API client
│   │   └── client.go            # API communication
│   │
│   ├── config/                  # Configuration
│   │   └── types.go             # Config structures (Mode, EnrichmentBackendConfig)
│   │
│   ├── metrics/                 # Prometheus metrics
│   │   └── prometheus.go        # Flow tracking + anomaly detection metrics
│   │
│   └── logger/                  # Structured logging
│       └── logger.go            # Zap logger setup
│
├── docs/
│   ├── remediation.md           # CIS control remediation guide
│   └── architecture.md          # Architecture overview
│
├── config/
│   ├── elf-owl.yaml             # Legacy default configuration
│   ├── profiles/                # Deployment profiles (NEW)
│   │   ├── elf-owl.gateway.yaml       # Gateway deployment (network-behavior, bare-metal)
│   │   ├── elf-owl.baremetal.yaml     # Bare-metal deployment (network-behavior, high-perf)
│   │   ├── elf-owl.vm.yaml            # VM deployment (network-behavior, minimal resources)
│   │   ├── elf-owl.kubernetes.yaml    # Kubernetes deployment (compliance, K8s enrichment)
│   │   └── elf-owl.comprehensive.yaml # Comprehensive deployment (dual-mode, maximum resources)
│   └── rules/                   # Rule definitions
│       ├── network-behavior.yaml # Network behavior anomaly detection rules (NEW)
│       └── cis-compliance.yaml   # CIS control compliance rules (NEW)
│
├── deploy/
│   ├── helm/                    # Helm chart
│   └── kustomize/               # Kustomize overlays
│
└── test/
    ├── fixtures/                # Test data
    └── integration/             # Integration tests
```

### Key File Descriptions

#### `pkg/network/flow_tracker.go` (327 LOC) - NEW
- **Purpose:** Bidirectional flow correlation and state tracking
- **Key Types:**
  - `FlowKey` - Canonical tuple (IP1, Port1, IP2, Port2, Protocol, NetnsID)
  - `FlowState` - Enum: NEW, ESTABLISHED, CLOSING, CLOSED
  - `FlowRecord` - Flow state, bytes, packets, timestamps, close reason
  - `FlowTracker` - Active flow management with TTL and LRU eviction
- **Key Functions:**
  - `AddOrUpdateFlow()` - Create or update bidirectional flow
  - `CloseFlow()` - Mark flow as closed with reason
  - `ExpireOldFlows()` - TTL-based flow expiry
- **Features:** Canonical ordering for order-independent matching, LRU eviction when limits exceeded, emits closed flows to channel

#### `pkg/enrichment/enricher.go` - Backend-Agnostic Interface (NEW)
- **Purpose:** Define pluggable enrichment interface
- **Key Interface:**
  - `Enricher` - Backend-agnostic interface with methods for all event types
  - `EnrichmentCapabilities` - Report backend capabilities
- **Implementations:** K8sEnricher, BareMetalEnricher

#### `pkg/enrichment/backends/baremetal_enricher.go` (370+ LOC) - NEW
- **Purpose:** Bare-metal event enrichment (hostname, process, SELinux)
- **Key Functions:**
  - `EnrichNetworkEvent()` - Add hostname, process info, user context, SELinux
  - `reverseDNS()` - Reverse DNS lookup with caching
  - `lookupProcessInfo()` - Extract process info from /proc
  - `readSELinuxContext()` - Read SELinux context
- **Features:** Hostname and process info caching with configurable TTLs

#### `pkg/rules/engine.go` - Dual-Mode Rule Engine
- **Purpose:** Mode-aware rule matching (network-behavior, compliance, dual)
- **Key Additions:**
  - `Mode` field: RuleModeBehavior, RuleModeCompliance, RuleModeDual
  - `NewEngineWithMode()` - Factory function for mode-specific engine
- **Behavior:** Loads appropriate rule sets based on mode

#### `pkg/rules/cis_compliance.go` (600+ LOC) - NEW
- **Purpose:** Define all 48 automated CIS Kubernetes v1.8 controls
- **Structure:** Array of `Rule` objects with conditions
- **Variable:** `CISCompliance` (backward-compatible alias: `CISControls`)
- **Rule Categories:**
  - Pod Security Context (8 rules: CIS 4.2.x)
  - Container Image & Registry (6 rules: CIS 4.3.x)
  - Resource Management (5 rules: CIS 4.4.x)
  - Network Policy (5 rules: CIS 4.6.x)
  - RBAC & Access Controls (10 rules: CIS 5.x.x)
  - Advanced Security Context (9 rules: CIS 4.7-4.9)

#### `pkg/rules/network_behavior.go` (120+ LOC) - NEW
- **Purpose:** Network anomaly detection rules
- **Rules:**
  - NET_BEHAVIOR_001: DDoS Flood Detection (high-volume connections/packets)
  - NET_BEHAVIOR_002: Data Exfiltration Suspected (large outbound data transfer)
  - NET_BEHAVIOR_003: Persistent Tunnel or Long-Lived Connection (sustained connections)
  - NET_BEHAVIOR_004: Unusual Protocol Combination (protocol mismatch anomalies)
  - NET_BEHAVIOR_005: Rapid Connection Retries (excessive retries indicating issues/attacks)
- **Variable:** `NetworkBehavior`

#### `pkg/rules/loader.go` - Mode-Aware Rule Loading
- **New Functions:**
  - `LoadNetworkBehaviorRules()` - File → ConfigMap → hardcoded fallback
  - `LoadComplianceRules()` - File → ConfigMap → hardcoded fallback
  - `LoadDualModeRules()` - Combines both rule sets

#### `pkg/kubernetes/client.go` (600+ LOC)
- **Purpose:** K8s API client for metadata extraction (now backend, optional)
- **Key Functions:**
  - `GetPodMetadata()` - Retrieve pod spec and status
  - `GetNetworkPolicyStatus()` - Evaluate network policies
  - `GetServiceAccountMetadata()` - RBAC information
  - `GetRBACLevel()` - Calculate privilege escalation level
  - `selectorMatches()` - Label selector matching with MatchExpressions

#### Configuration Profiles (NEW)
- **gateway.yaml** - Network-behavior mode, bare-metal enrichment, gateway-optimized
- **baremetal.yaml** - Network-behavior mode, bare-metal enrichment, high-performance
- **vm.yaml** - Network-behavior mode, bare-metal enrichment, minimal resources
- **kubernetes.yaml** - Compliance mode, K8s enrichment, CIS control validation
- **comprehensive.yaml** - Dual-mode (behavior + compliance), K8s enrichment, maximum resources

### Critical Implementation Details

#### Bidirectional Flow Tracking

1. **Flow Key Canonicalization:** Min/max IP ordering ensures bidirectional events map to same flow
2. **State Transitions:** NEW → ESTABLISHED → CLOSING → CLOSED
3. **TTL-Based Expiry:** Configurable per deployment (30min gateway, 60min LB, 10min VM)
4. **LRU Eviction:** Removes least-recently-used flows when limits exceeded
5. **Metrics:** Records flow creation, closure (by reason), byte/packet counts

#### Pluggable Enrichment Architecture

1. **Backend Selection:** Config-driven choice (bare-metal, kubernetes, disabled)
2. **Bare-Metal Enrichment:** Hostname (reverse DNS), process info (/proc), OS context, SELinux
3. **Kubernetes Enrichment:** Pod metadata, service account, RBAC level, network policies
4. **Flow Context Injection:** FlowID, duration, bytes in/out, packets in/out, state transitions
5. **Caching:** Backend-specific TTLs for performance (hostname, process, pod metadata)

#### Dual-Mode Rule Engine

1. **Mode Selection:** network-behavior, compliance, or dual
2. **Rule Loading:** Mode-aware loading combines appropriate rule sets
3. **Network-Behavior Mode:** DDoS, port scan, data exfil, tunneling detection
4. **Compliance Mode:** 48 CIS Kubernetes v1.8 controls
5. **Dual Mode:** Both rule sets evaluated simultaneously (performance trade-off)

#### Event Enrichment Pipeline

1. **Network Event Capture:** eBPF captures network events (sockets, packets)
2. **Flow Tracking:** AddOrUpdateFlow() correlates bidirectional events
3. **Backend Enrichment:** Selected enricher adds context (hostname, pod, process)
4. **Rule Matching:** Mode-aware engine matches against appropriate rules
5. **Violation/Anomaly Generation:** Create events for rule violations or anomalies
6. **Webhook/API Delivery:** Push violations and flow summaries to Owl SaaS

#### RBAC Privilege Calculation (K8s Enrichment)

- **Level 0:** Restricted (0 permissions)
- **Level 1:** Standard (1-10 permissions)
- **Level 2:** Elevated (11-100 permissions)
- **Level 3:** Admin (100+ permissions)

#### Label Selector Matching (K8s Enrichment)

- **MatchLabels:** Direct key=value matches
- **MatchExpressions:** Operator-based matching (In, NotIn, Exists, DoesNotExist)
- **Empty Selector:** Matches all pods

---

## Development Workflow

### Standard Development Steps

1. **Read existing code** - Understand current implementation
2. **Create plan** - Document proposed changes
3. **Get approval** - Wait for user sign-off
4. **Implement** - Make changes with anchor comments
5. **Add tests** - Test new functionality
6. **Commit** - Use proper commit message types
7. **Verify** - Run full test suite

### Running Tests

```bash
# Run all unit tests
go test ./pkg/...

# Run specific package tests
go test ./pkg/rules/... -v

# Run integration tests
go test ./test/integration/...

# Run with coverage
go test -cover ./pkg/...

# Run specific test
go test -run TestEnginMatch ./pkg/rules/
```

### Building the Project

```bash
# Build agent binary
go build -o elf-owl cmd/elf-owl/main.go

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 go build -o elf-owl-linux cmd/elf-owl/main.go
```

### Code Style

- Follow Go idioms and conventions
- Use `gofmt` for formatting
- Keep functions focused and testable
- Write clear variable names
- Add comments for non-obvious logic
- Use structured logging with zap

---

## Important Constraints

### DO

- ✅ Always create a plan first
- ✅ Wait for explicit user approval
- ✅ Include anchor comments in all modified code
- ✅ Use correct commit message types
- ✅ Write clear commit messages
- ✅ Read files before editing
- ✅ Test changes after implementation
- ✅ Document complex logic
- ✅ Handle errors gracefully
- ✅ Consider backward compatibility

### DO NOT

- ❌ Make code changes without an approved plan
- ❌ Skip anchor comments in modified sections
- ❌ Use incorrect commit message types
- ❌ Over-engineer solutions
- ❌ Add unnecessary features beyond the request
- ❌ Make commits without proper messages
- ❌ Modify code without reading it first
- ❌ Assume code behavior without verification
- ❌ Break existing tests
- ❌ Ignore error handling

---

## Common Development Tasks

### Task 1: Add a New Network Behavior Detection Rule

**Plan Structure:**
1. Add rule to `pkg/rules/network_behavior.go` array
2. Define conditions based on FlowRecord fields (bytes, packets, duration, state transitions)
3. Add unit test to `pkg/rules/engine_test.go` testing both network-behavior and dual modes
4. Add Prometheus metrics recording if needed
5. Document detection logic in code comments

**Anchor Comment Example:**
```go
// ANCHOR: [Rule ID]: [Rule Title] - Feature: Network behavior detection - [DATE]
// Detects [what it detects]. Requires [flow field] condition match and [threshold].
// Triggers for [specific scenario] which indicates [security risk].
```

### Task 2: Add a New Compliance Control Rule

**Plan Structure:**
1. Add rule to `pkg/rules/cis_compliance.go` array
2. Define conditions based on eBPF event fields and K8s enrichment
3. Add unit test to `pkg/rules/engine_test.go` testing compliance and dual modes
4. Add remediation guidance to `docs/remediation.md`
5. Update K8s enrichment backend if new API calls needed

**Anchor Comment Example:**
```go
// ANCHOR: CIS [Control ID]: [Control Title] - Feature: CIS Kubernetes v1.8 - [DATE]
// Detects [violation description]. Requires [enrichment type] and [condition] match.
```

### Task 3: Implement a New Enrichment Backend

**Plan Structure:**
1. Create `pkg/enrichment/backends/[backend]_enricher.go` implementing Enricher interface
2. Create `pkg/enrichment/backends/[backend]_config.go` with configuration struct
3. Implement all Enricher interface methods (EnrichNetworkEvent, EnrichProcessEvent, etc.)
4. Add caching where appropriate for performance
5. Add unit tests for new backend
6. Update `pkg/agent/agent.go` NewAgent() to select new backend
7. Create config profile in `config/profiles/elf-owl.[deployment].yaml`

**Anchor Comment Example:**
```go
// ANCHOR: [Backend] enrichment backend - Feature: [Backend] integration - [DATE]
// Provides context for [backend-specific details] via [integration method].
// Supports [features]. Caches [data type] for performance.
```

### Task 4: Add Flow Tracking Features

**Plan Structure:**
1. Identify new flow state or metric needed
2. Modify `pkg/network/flow_tracker.go` FlowRecord or FlowTracker methods
3. Add supporting Prometheus metrics in `pkg/metrics/prometheus.go`
4. Update `pkg/enrichment/types.go` NetworkContext if new flow fields needed
5. Add unit tests covering state transitions and eviction scenarios
6. Update flow TTL configuration if needed in config profiles

**Anchor Comment Example:**
```go
// ANCHOR: Flow tracking: [feature name] - Feature: [Enhancement description] - [DATE]
// Tracks [what is tracked] for [purpose]. Exposed via [metrics/fields].
// Eviction/TTL behavior: [describe].
```

### Task 5: Fix a Dual-Mode Rule Matching Bug

**Plan Structure:**
1. Identify bug in network-behavior, compliance, or both modes
2. Read affected rule(s) in `cis_compliance.go` or `network_behavior.go`
3. Trace through `pkg/rules/engine.go` mode-aware matching logic
4. Create test case that reproduces bug in affected mode(s)
5. Implement fix with anchor comment explaining root cause
6. Verify fix doesn't break other modes (use all 3 modes in testing)

**Anchor Comment Example:**
```go
// ANCHOR: [Rule ID] [mode] mode matching - Bug #N: [Issue description] - [DATE]
// [Mode]-only bug: [what went wrong]. Changed to [solution]. Verified with dual-mode test.
```

### Task 6: Update Rule Loader for New Mode

**Plan Structure:**
1. Modify `LoadRulesFromFile()` or `LoadRulesFromConfigMap()` if needed for new source
2. Update mode-aware loading functions (LoadNetworkBehaviorRules, LoadComplianceRules, LoadDualModeRules)
3. Add error handling and validation for new rule source
4. Add unit tests for mode-specific loading scenarios
5. Verify fallback chain (File → ConfigMap → hardcoded) still works for all modes

**Anchor Comment Example:**
```go
// ANCHOR: Rule loading from [source] - Feature: [Enhancement] - [DATE]
// Implements [functionality] for [modes]. Supports [sources] with fallback [behavior].
```

---

## File Modification Checklist

When modifying existing files:

1. **Read First** - Always read the file completely before editing
2. **Identify Impact** - Note all functions/sections affected
3. **Preserve Style** - Match existing code style and patterns
4. **Add Anchors** - Include anchor comments in modified sections
5. **Test Scope** - Consider what tests are affected
6. **Document Changes** - Update relevant documentation
7. **Commit Atomically** - One logical change per commit

---

## Special Cases

### Security-Sensitive Code

- Extra-detailed plan required
- All edge cases must be covered
- Must verify no vulnerabilities introduced
- Consider authorization and authentication implications

### Performance-Critical Code

- Plan must include performance impact analysis
- Consider benchmarking existing vs. new code
- Anchor comments must explain optimization
- Document any trade-offs

### Configuration/Flag Changes

- Must document default values
- Must explain impact on existing deployments
- Include migration guidance if breaking

### Data Structure Changes

- Plan must include migration strategy
- Must document backward compatibility
- Explain data transformation logic
- Update all code that uses the structure

---

## Questions & Support

If any guideline is unclear:
- Ask user for clarification before proceeding
- Do not guess or assume behavior
- Document the clarification in comments
- Update this CLAUDE.md if guideline is ambiguous

For questions about:
- Architecture: Refer to README.md and SPRINT.md
- Code structure: Check project structure section above
- CIS controls: See docs/remediation.md
- Implementation details: Check commit messages and anchor comments

---

## Quick Reference

### When to Anchor Comment
```
New functions/methods → YES
Bug fixes → YES
Complex logic → YES
Security-sensitive code → YES
Simple assignments → NO
Standard library usage → NO
Already-commented code → NO
```

### When to Plan
```
Any code changes → YES
Adding functions → YES
Modifying existing code → YES
Fixing bugs → YES
Refactoring → YES
Documentation only → MAYBE
Tests only → MAYBE
```

### Commit Type Selection
```
New feature → feat
Bug fix → fix
Test additions → test
Documentation → docs
Code cleanup → refactor
Formatting → style
Performance → perf
Maintenance → chore
CI/CD changes → ci
```

---

**Last Updated:** December 27, 2025
**Status:** Active - Binding Guidelines
**Version:** 1.0.0
**Authority:** elf-owl Project Standards
