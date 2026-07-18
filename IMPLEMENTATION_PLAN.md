# ElfOwl Network-Behavior-Centric Implementation Plan

**Status:** Approved for Implementation  
**Date:** July 18, 2026  
**Scope:** Network-behavior-centric monitoring with pluggable enrichment backends  
**MVP Environments:** Gateway, Bare-Metal, VM  
**Mode Options:** Network-behavior (default), Compliance (optional), Dual (both)

---

## Executive Summary

This implementation transforms ElfOwl from a Kubernetes-centric compliance agent into a **network-behavior-centric gateway/firewall monitoring platform** with **optional compliance monitoring**. Key changes:

- **Pluggable enrichment:** Backend selection (bare-metal, Kubernetes, cloud)
- **Dual-mode rules:** Network anomaly detection OR CIS compliance (or both)
- **Bidirectional flow tracking:** Conntrack-style flow correlation
- **Environment-agnostic core:** NetworkContext simplified, K8s fields optional
- **Optional K8s:** Kubernetes compliance support available but not default

---

## Implementation Phases (25 Tasks)

### Phase 1: Decoupling from K8s (Tasks #1-2)
Separate CIS compliance rules from network behavior rules. Create pluggable enrichment interface.

- **Task #1:** Separate CIS compliance rules → `pkg/rules/compliance/`
- **Task #2:** Create `enrichment.Enricher` interface

**Checkpoint:** Rules are independent; enricher is interface-based

---

### Phase 2: Enrichment Backends (Tasks #3-4)
Implement bare-metal enricher and refactor existing K8s enricher as pluggable backend.

- **Task #3:** Implement `BareMetalEnricher` (hostname, /proc, reverse DNS, SELinux)
- **Task #4:** Refactor K8s enricher → `pkg/enrichment/backends/k8s_enricher.go`

**Checkpoint:** Both enrichers implemented; can switch via config

---

### Phase 3: Data Structures (Tasks #5-6)
Simplify `NetworkContext` to be environment-agnostic. Add flow tracker.

- **Task #5:** Remove K8s fields from `NetworkContext`; add flow fields
- **Task #6:** Implement `FlowTracker` with bidirectional correlation (4-state machine)

**Checkpoint:** Core data structures simplified; flow tracking operational

---

### Phase 4: Rule Engine (Tasks #7-8)
Implement dual-mode rule evaluation (network-behavior, compliance, dual).

- **Task #7:** Add mode field to `Engine`; implement mode-aware `Match()`
- **Task #8:** Implement mode-aware rule loader (file → ConfigMap → hardcoded)

**Checkpoint:** Rule engine can switch modes; rules load correctly

---

### Phase 5: Agent Integration (Tasks #9-12)
Wire everything together: backend selection, flow tracker, enrichment field population.

- **Task #9:** Add `EnrichmentBackendConfig` and `RulesConfig.Mode` to config
- **Task #10:** Integrate `FlowTracker` into `Agent`; add flow summary emission goroutine
- **Task #11:** Implement backend selection logic in `NewAgent()`
- **Task #12:** Update enrichers to populate flow fields

**Checkpoint:** Agent initializes correct backend; flows tracked and enriched

---

### Phase 6: Webhook Events (Tasks #13-14)
Define `FlowSummaryEvent` type and emit flow lifecycle events.

- **Task #13:** Add `FlowSummaryEvent` type and `EventTypeFlowSummary` constant
- **Task #14:** Emit flow summaries when flows close

**Checkpoint:** Flow summary events pushed to webhook

---

### Phase 7: Configuration Profiles (Tasks #15-17)
Create environment-specific YAML profiles for all deployment scenarios.

- **Task #15:** Gateway profile (network-behavior mode, bare-metal backend)
- **Task #16:** Bare-metal and VM profiles
- **Task #17:** Kubernetes (compliance) and comprehensive (dual) profiles

**Checkpoint:** All deployment scenarios have ready-to-use configs

---

### Phase 8: Metrics (Task #18)
Add network-behavior-specific Prometheus metrics.

- **Task #18:** Active flows, bytes transferred, anomalies detected, TTL/memory events

**Checkpoint:** Metrics available for monitoring

---

### Phase 9: Testing (Tasks #19-23)
Unit and integration tests for all components.

- **Task #19:** Flow tracker tests
- **Task #20:** Enricher backend tests
- **Task #21:** Dual-mode rule engine tests
- **Task #22:** Integration tests (backend selection, pipeline)
- **Task #23:** Webhook flow event tests

**Checkpoint:** All tests passing

---

### Phase 10: Documentation & Verification (Tasks #24-25)
Update CLAUDE.md and verify end-to-end functionality.

- **Task #24:** Update CLAUDE.md with new architecture
- **Task #25:** Manual end-to-end test with gateway and K8s profiles

**Checkpoint:** Complete, documented, verified

---

## File Structure After Implementation

```
elf-owl/
├── pkg/
│   ├── enrichment/
│   │   ├── enricher.go           # Interface definitions
│   │   ├── types.go              # Simplified NetworkContext + flow fields
│   │   └── backends/
│   │       ├── baremetal_enricher.go      (NEW)
│   │       ├── baremetal_enricher_test.go (NEW)
│   │       ├── k8s_enricher.go            (NEW - refactored)
│   │       └── k8s_enricher_test.go       (NEW)
│   │
│   ├── network/
│   │   ├── flow_tracker.go       (NEW - bidirectional flow correlation)
│   │   └── flow_tracker_test.go  (NEW)
│   │
│   ├── rules/
│   │   ├── engine.go             # Dual-mode rule matching
│   │   ├── loader.go             # Mode-aware rule loading
│   │   ├── compliance/
│   │   │   └── cis_kubernetes_v1_8.go    (NEW - moved from cis_mappings.go)
│   │   ├── behavior/
│   │   │   ├── network_behavior.go       (NEW - anomaly detection rules)
│   │   │   └── network_behavior.go_test  (NEW)
│   │   └── cis_mappings.go       # (kept for backward compat, re-exports)
│   │
│   ├── agent/
│   │   ├── agent.go              # Backend selection, flow tracker integration
│   │   ├── config.go             # EnrichmentBackendConfig, RulesConfig.Mode
│   │   └── webhook.go            # FlowSummaryEvent type
│   │
│   └── metrics/
│       └── prometheus.go         # Network behavior metrics
│
├── config/
│   ├── profiles/
│   │   ├── elf-owl.gateway.yaml        (NEW)
│   │   ├── elf-owl.baremetal.yaml      (NEW)
│   │   ├── elf-owl.vm.yaml             (NEW)
│   │   ├── elf-owl.kubernetes.yaml     (NEW)
│   │   └── elf-owl.comprehensive.yaml  (NEW)
│   ├── gateway-services.yaml           (NEW - port→service mapping)
│   └── elf-owl.yaml                    (existing, kept for compat)
│
└── CLAUDE.md                           # Updated with new architecture
```

---

## Configuration Modes

### Gateway/Firewall (Network-Behavior-Centric)
```yaml
agent:
  rules:
    mode: "network-behavior"
  enrichment_backend:
    type: "bare-metal"
```
**Rules:** DDoS, port scanning, data exfiltration, tunnels  
**Enrichment:** Hostname, process, SELinux (lightweight)  
**Use Case:** Firewalls, network gateways, SOHO devices

---

### Kubernetes (Compliance-Centric)
```yaml
agent:
  rules:
    mode: "compliance"
  enrichment_backend:
    type: "kubernetes"
```
**Rules:** 48 CIS Kubernetes controls  
**Enrichment:** Pod, service account, RBAC, network policies (full K8s)  
**Use Case:** K8s security audits, CIS compliance

---

### Comprehensive (Dual Mode)
```yaml
agent:
  rules:
    mode: "dual"
  enrichment_backend:
    type: "kubernetes"
```
**Rules:** Both network anomalies AND CIS controls  
**Enrichment:** Full K8s context  
**Use Case:** Comprehensive security (network + compliance)

---

## Git Commits (In Order)

```bash
1. feat: separate CIS rules from network behavior rules
   - Move CIS to pkg/rules/compliance/
   - Extract network behavior to pkg/rules/behavior/

2. refactor: create pluggable enrichment interface
   - Define enrichment.Enricher interface
   - Update Agent to use interface

3. feat: implement bare-metal enrichment backend
   - pkg/enrichment/backends/baremetal_enricher.go
   - Hostname, /proc, reverse DNS, SELinux support

4. refactor: move K8s enricher to pluggable backend
   - Create pkg/enrichment/backends/k8s_enricher.go
   - Maintain existing functionality

5. refactor: simplify NetworkContext for environment-agnostic use
   - Remove K8s-specific fields
   - Add pluggable enrichment fields
   - Add flow tracking fields

6. feat: add bidirectional flow tracking
   - pkg/network/flow_tracker.go
   - 4-state machine (NEW, ESTABLISHED, CLOSING, CLOSED)
   - TTL and memory-based eviction

7. feat: implement dual-mode rule engine
   - network-behavior, compliance, dual modes
   - Mode-aware rule evaluation

8. feat: implement mode-aware rule loading
   - Load rules by mode (file → ConfigMap → hardcoded)
   - Separate loader chains per mode

9. feat: add enrichment backend configuration
   - EnrichmentBackendConfig struct
   - RulesConfig.Mode field
   - Auto-detection based on backend type

10. feat: integrate flow tracker into agent
    - FlowTracker field in Agent
    - Flow summary emission goroutine
    - Graceful shutdown barrier

11. feat: implement enrichment backend selection
    - Switch on config type (bare-metal, kubernetes, disabled)
    - Initialize correct backend in NewAgent()

12. feat: populate flow fields during enrichment
    - Call FlowTracker.AddOrUpdateFlow()
    - Populate flow tracking fields in NetworkContext

13. feat: add FlowSummaryEvent webhook event type
    - EventTypeFlowSummary constant
    - FlowSummaryEvent struct with all metadata

14. feat: emit flow summary events from agent
    - Goroutine drains FlowTracker.ClosedFlows()
    - Convert FlowRecord to FlowSummaryEvent
    - Send to WebhookPusher

15. feat: create gateway configuration profile
    - config/profiles/elf-owl.gateway.yaml
    - config/gateway-services.yaml (port mappings)

16. feat: create bare-metal and VM profiles
    - config/profiles/elf-owl.baremetal.yaml
    - config/profiles/elf-owl.vm.yaml

17. feat: create K8s and comprehensive profiles
    - config/profiles/elf-owl.kubernetes.yaml (compliance)
    - config/profiles/elf-owl.comprehensive.yaml (dual)

18. feat: add network behavior analysis metrics
    - Flow counters, byte counters, anomaly counters
    - TTL/memory eviction metrics

19. test: add flow tracker unit tests
    - Bidirectional matching, state machine, TTL, eviction

20. test: add enricher backend unit tests
    - Bare-metal and K8s enricher tests

21. test: add dual-mode rule engine tests
    - Mode-specific evaluation

22. test: add integration tests
    - Backend selection, flow tracking, rule evaluation

23. test: add webhook flow summary tests
    - Event formatting, emission, batching

24. docs: update CLAUDE.md with new architecture
    - Dual-mode, pluggable enrichment, profiles

25. test: verify end-to-end with test deployment
    - Gateway and K8s profiles
```

---

## Deployment Checklist

### Pre-Implementation
- [ ] Review and approve implementation plan (DONE)
- [ ] Create task list and set dependencies (DONE)
- [ ] Verify file paths and structure

### Phase 1-4: Core Architecture
- [ ] Task #1: Rule separation
- [ ] Task #2: Enrichment interface
- [ ] Task #3-4: Backend implementations
- [ ] Task #5-6: Data structures and flow tracking
- [ ] Task #7-8: Dual-mode rules

**Checkpoint Verification:**
```bash
go test ./pkg/rules/... -v
go test ./pkg/enrichment/... -v
go test ./pkg/network/... -v
```

### Phase 5-6: Integration & Webhook
- [ ] Task #9-12: Agent integration
- [ ] Task #13-14: Webhook events

**Checkpoint Verification:**
```bash
go build cmd/elf-owl/main.go
./elf-owl --config config/profiles/elf-owl.gateway.yaml
# Verify no startup errors
```

### Phase 7-8: Config & Metrics
- [ ] Task #15-18: Configuration profiles and metrics

### Phase 9: Testing
- [ ] Task #19-23: All test suites passing

**Verification:**
```bash
go test ./... -v
go test ./... -cover
```

### Phase 10: Documentation & End-to-End
- [ ] Task #24: CLAUDE.md updated
- [ ] Task #25: End-to-end test with real deployment

---

## Rollback Plan

If any phase fails:
1. **Phase 1-2:** Can rollback by reverting enrichment interface changes; existing K8s enricher still works
2. **Phase 3-4:** Flow tracking can be disabled in config; doesn't break existing pipeline
3. **Phase 5+:** Backward compatible; existing configs still work with auto-detected mode

**Safety:** All changes are additive; no breaking changes to existing deployments until explicitly configured to use new mode.

---

## Success Criteria

✅ Gateway deployment (network-behavior mode) works end-to-end  
✅ K8s deployment (compliance mode) works end-to-end  
✅ All tests passing  
✅ Bidirectional flow correlation verified  
✅ FlowSummaryEvent emitted correctly  
✅ Mode switching works (via config change, no code recompile)  
✅ Metrics available and accurate  
✅ Documentation updated

---

## Next Steps

1. Start with **Task #1** (rule separation)
2. Follow task dependencies in order
3. After each phase checkpoint, verify against checklist
4. Daily progress updates tied to completed tasks

**Ready to begin?** Start with Task #1 next.
