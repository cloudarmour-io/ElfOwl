# `pkg/rules/` — CIS Rule Engine

**Package:** `rules`
**Purpose:** Matches enriched events against CIS Kubernetes v1.8 control definitions. Provides the rule type model, the matching engine, a YAML/ConfigMap loader, and the hardcoded `CISControls` slice.

---

## Files

| Source file | Doc | Description |
|---|---|---|
| [engine.go](../../../../pkg/rules/engine.go) | [engine.md](./engine.md) | `Engine`, `Rule`, `Condition`, `Violation`, `Match`, `extractField` |
| [cis_mappings.go](../../../../pkg/rules/cis_mappings.go) | [cis_mappings.md](./cis_mappings.md) | `CISControls` — all 48 hardcoded rule definitions |
| [loader.go](../../../../pkg/rules/loader.go) | [loader.md](./loader.md) | `LoadRulesFromFile`, `LoadRulesFromConfigMap`, YAML types |

---

## Pipeline

```
pkg/agent
    │
    ▼
Engine.Match(EnrichedEvent)
    │
    ├── filter by EventType
    ├── evaluateCondition (per condition, AND semantics)
    │       ├── extractField(event, fieldPath)
    │       └── operator: equals / not_equals / contains / in / not_in
    │                      greater_than / less_than / regex
    │
    └── []*Violation  →  pkg/evidence Buffer.Enqueue  →  push to Owl SaaS
```

---

## Rule Sources (fallback chain)

```
NewEngineWithConfig(EngineConfig{...})
    │
    ├─ 1. YAML file  (RuleFilePath)
    ├─ 2. ConfigMap  (K8s API: ConfigMapName/Namespace)
    └─ 3. Hardcoded  (CISControls in cis_mappings.go)
```

`NewEngine(filePath...)` — simpler: file or hardcoded, no ConfigMap path.

---

## Coverage Summary

| Category | Control IDs | Count |
|---|---|---|
| Pod Security Context | CIS_4.2.1–4.2.8 | 8 |
| Legacy Pod Security | CIS_4.5.1–4.5.5 | 4 |
| ServiceAccount (legacy) | CIS_4.1.1 | 1 |
| Container Image & Registry | CIS_4.3.1–4.3.6 | 6 |
| Resource Management | CIS_4.4.1–4.4.5 | 5 |
| Network Policy | CIS_4.6.1–4.6.5 | 5 |
| Advanced Security | CIS_4.7.1–4.9.3 | 9 |
| RBAC & Access Controls | CIS_5.1.1–5.5.1 | 9 |
| **Total** | | **47** |

---

## Related Packages

| Package | Role |
|---|---|
| [pkg/enrichment/types.go](../enrichment/types.md) | `EnrichedEvent` — input to `Match` |
| [pkg/agent/agent.go](../agent/agent.md) | Calls `engine.Match`; passes violations to buffer |
| [pkg/evidence/buffer.go](../evidence/buffer.md) | Stores `[]*Violation` alongside event |
