# `pkg/rules/engine.go` — Rule Matching Engine

**Package:** `rules`
**Path:** `pkg/rules/engine.go`
**Lines:** 708

---

## Overview

Core matching engine. Iterates `Engine.Rules`, filters by event type, evaluates all conditions with AND semantics, and returns a `[]*Violation` slice. Also contains all type definitions for the rules subsystem.

---

## Types

### `Engine`

```go
type Engine struct {
    Rules  []*Rule
    Logger *zap.Logger
}
```

### `EngineConfig`

```go
type EngineConfig struct {
    RuleFilePath       string
    ConfigMapName      string
    ConfigMapNamespace string
    ConfigMapDataKey   string                // default: "rules.yaml"
    K8sClientset       *kubernetes.Clientset
    Ctx                context.Context
    StrictSource       bool                  // if true, error on source failure instead of falling back
}
```

### `Rule`

```go
type Rule struct {
    ControlID  string
    Title      string
    Severity   string       // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    EventTypes []string     // matched against EnrichedEvent.EventType
    Conditions []Condition  // all must match (AND)
}
```

### `Condition`

```go
type Condition struct {
    Field         string      // dot-path into EnrichedEvent (e.g. "container.host_network")
    Operator      string
    Value         interface{}
    compiledRegex *regexp.Regexp  // cached after prepareRuleCaches
}
```

### `Violation`

```go
type Violation struct {
    ControlID      string
    Title          string
    Severity       string
    Timestamp      time.Time
    Pod            *enrichment.K8sContext
    Container      *enrichment.ContainerContext
    Description    string         // "<ControlID>: <Title>"
    RemediationRef string         // "docs/remediation#<ControlID>"
}
```

---

## Construction

### `NewEngine(ruleFilePath ...string) (*Engine, error)`

Variadic for backward compatibility. If a path is provided: attempt `LoadRulesFromFile`; on error, warn and fall back to `loadCISRules()`. No ConfigMap path. Calls `prepareRuleCaches` after loading.

### `NewEngineWithConfig(config *EngineConfig) (*Engine, error)`

Full fallback chain:

```
1. RuleFilePath set?
   └─ LoadRulesFromFile → on error:
       └─ StrictSource? → return error
          else: ConfigMap configured? → LoadRulesFromConfigMap → on error:
              └─ loadCISRules()
2. ConfigMap configured (no file)?
   └─ LoadRulesFromConfigMap → on error:
       └─ StrictSource? → return error
          else: loadCISRules()
3. Neither?
   └─ loadCISRules()
```

Logs `rule_source` (`"file"`, `"configmap"`, or `"hardcoded"`) at `Info` level.

---

## `Match(event *enrichment.EnrichedEvent) []*Violation`

```
for each rule:
    if event.EventType not in rule.EventTypes → skip
    for each condition:
        if !evaluateCondition(event, cond) → break (AND logic)
    if all conditions passed:
        append Violation{...}
return violations
```

Non-matching rules and rules with failed conditions are silently skipped. Never returns an error — a nil `extractField` result causes the condition to return `false`.

---

## `evaluateCondition`

Calls `extractField` then dispatches on `Condition.Operator`:

| Operator | Aliases | Logic |
|---|---|---|
| `equals` | `==` | `normalizedEqual(fieldValue, cond.Value)` |
| `not_equals` | `!=` | `!normalizedEqual(...)` |
| `contains` | — | `strings.Contains` (string only) |
| `in` | — | `valueInSlice(cond.Value, fieldValue)` — cond.Value must be a slice |
| `not_in` | — | `!valueInSlice(...)` |
| `greater_than` | — | `toFloat(field) > toFloat(cond.Value)` |
| `less_than` | — | `toFloat(field) < toFloat(cond.Value)` |
| `regex` | — | `compiledRegex.MatchString(fieldValue)` (uses pre-compiled cache) |

`normalizedEqual` tries numeric comparison first (`toFloat`), then boolean (`toBool`), then string, then `reflect.DeepEqual`. This allows rules to compare `Value: 0` against a `uint32` field value without type mismatches.

`toFloat` handles `int`, `int32`, `int64`, `uint`, `uint32`, `uint64`, `float32`, `float64`.

`toBool` handles `bool` and parses `"true"`/`"false"` strings via `strconv.ParseBool`.

---

## `prepareRuleCaches`

Called once after rule loading. Iterates all conditions with `Operator == "regex"` and pre-compiles their patterns into `cond.compiledRegex`. Invalid patterns are logged as `Warn` and left nil (the `evaluateCondition` path re-compiles on demand as a fallback).

---

## `extractField`

Large switch on a dot-path string. Returns `interface{}` — `nil` means field unavailable (e.g. nil sub-struct pointer). All extracted values are typed (e.g. `int`, `bool`, `string`) — `normalizedEqual` handles cross-type comparison.

**Complete field path list:**

| Path | Source field |
|---|---|
| `event_type` | `event.EventType` |
| `kubernetes.namespace` | `K8sContext.Namespace` |
| `kubernetes.pod_name` | `K8sContext.PodName` |
| `kubernetes.pod_uid` | `K8sContext.PodUID` |
| `kubernetes.cluster_id` | `K8sContext.ClusterID` |
| `kubernetes.node_name` | `K8sContext.NodeName` |
| `kubernetes.service_account` | `K8sContext.ServiceAccount` |
| `kubernetes.has_default_deny_policy` | `K8sContext.HasDefaultDenyNetworkPolicy` |
| `kubernetes.image_registry` | `K8sContext.ImageRegistry` |
| `kubernetes.image_tag` | `K8sContext.ImageTag` |
| `kubernetes.rbac_enforced` | `K8sContext.RBACEnforced` |
| `kubernetes.rbac_level` | `K8sContext.RBACLevel` |
| `kubernetes.service_account_token_age` | `K8sContext.ServiceAccountTokenAge` |
| `kubernetes.service_account_permissions` | `K8sContext.ServiceAccountPermissions` |
| `kubernetes.rbac_policy_defined` | `K8sContext.RBACPolicyDefined` |
| `kubernetes.role_permission_count` | `K8sContext.RolePermissionCount` |
| `kubernetes.audit_logging_enabled` | `K8sContext.AuditLoggingEnabled` |
| `kubernetes.automount_service_account_token` | `K8sContext.AutomountServiceAccountToken` |
| `container.id` | `ContainerContext.ContainerID` |
| `container.name` | `ContainerContext.ContainerName` |
| `container.runtime` | `ContainerContext.Runtime` |
| `container.security_context.privileged` | `ContainerContext.Privileged` |
| `container.run_as_root` | `ContainerContext.RunAsRoot` |
| `container.allow_privilege_escalation` | `ContainerContext.AllowPrivilegeEscalation` (returns `nil` if `AllowPrivilegeEscalationKnown == false`) |
| `container.host_network` / `host_ipc` / `host_pid` | `ContainerContext.HostNetwork/IPC/PID` |
| `container.seccomp_profile` | `ContainerContext.SeccompProfile` |
| `container.apparmor_profile` | `ContainerContext.ApparmorProfile` |
| `container.image_pull_policy` | `ContainerContext.ImagePullPolicy` |
| `container.image_scan_status` | `ContainerContext.ImageScanStatus` |
| `container.image_registry_auth` | `ContainerContext.ImageRegistryAuth` |
| `container.image_signed` | `ContainerContext.ImageSigned` |
| `container.memory_limit` / `cpu_limit` / `memory_request` / `cpu_request` / `storage_request` | Resource fields |
| `container.read_only_filesystem` | `ContainerContext.ReadOnlyFilesystem` |
| `container.volume_type` | `ContainerContext.VolumeType` |
| `container.selinux_level` | `ContainerContext.SELinuxLevel` |
| `container.isolation_level` | `ContainerContext.IsolationLevel` |
| `container.kernel_hardening` | `ContainerContext.KernelHardening` |
| `process.uid` / `pid` / `command` | `ProcessContext` fields |
| `file.path` / `operation` | `FileContext` fields |
| `capability.name` / `allowed` | `CapabilityContext` fields |
| `network.ingress_restricted` / `egress_restricted` / `namespace_isolation` | `NetworkContext` fields |
| `dns.query_allowed` | `DNSContext.QueryAllowed` |

**`container.allow_privilege_escalation` special case:** returns `nil` when `AllowPrivilegeEscalationKnown == false`. This prevents rules from firing on events where the privilege escalation state was never set (avoids false positives from the K8s default when not explicitly configured).

**`kubernetes.automount_service_account_token` bug fix (Apr 20, 2026):** this case was missing, causing `CIS_5.2.1` conditions to always return `nil` and never fire.

---

## Key Anchor Comments

| Location | Anchor summary |
|---|---|
| `EngineConfig` | Flexible rule sourcing with file → ConfigMap → hardcoded fallback |
| `evaluateCondition` | Condition evaluation — operators, field extraction |
| `extractField` | `kubernetes.automount_service_account_token` — CIS_5.2.1 never-fires fix — Apr 20, 2026 |
| `container.allow_privilege_escalation` | Returns nil when `AllowPrivilegeEscalationKnown == false` |

---

## Related Files

| File | Relationship |
|---|---|
| [cis_mappings.go](./cis_mappings.md) | `CISControls` slice returned by `loadCISRules()` |
| [loader.go](./loader.md) | `LoadRulesFromFile`, `LoadRulesFromConfigMap` |
| [pkg/enrichment/types.go](../enrichment/types.md) | `EnrichedEvent` — input; all fields accessed via `extractField` |
| [pkg/agent/agent.go](../agent/agent.md) | Calls `engine.Match`; passes violations to `buffer.Enqueue` |
