# `pkg/rules/loader.go` — Rule Loader

**Package:** `rules`
**Path:** `pkg/rules/loader.go`
**Lines:** 184

---

## Overview

Loads `[]*Rule` from two external sources: a YAML file on disk and a Kubernetes ConfigMap. Both paths share the same YAML wire types and the same `convertYAMLToRule` validation/conversion function. Called by `NewEngineWithConfig` in the file → ConfigMap → hardcoded fallback chain.

---

## YAML Wire Types

### `RuleYAML`

```go
type RuleYAML struct {
    ControlID  string          `yaml:"controlID"`
    Title      string          `yaml:"title"`
    Severity   string          `yaml:"severity"`
    EventTypes []string        `yaml:"eventTypes"`
    Conditions []ConditionYAML `yaml:"conditions"`
}
```

### `ConditionYAML`

```go
type ConditionYAML struct {
    Field    string      `yaml:"field"`
    Operator string      `yaml:"operator"`
    Value    interface{} `yaml:"value"`
}
```

`Value` is `interface{}` to accept arbitrary YAML scalar types (string, bool, int, float, list). The YAML decoder unmarshals lists as `[]interface{}`, which `evaluateCondition` handles via `valueInSlice`.

---

## `LoadRulesFromFile(filePath string) ([]*Rule, error)`

```
1. Reject empty path → error
2. filepath.Abs(filePath) → resolvedPath
3. os.ReadFile(resolvedPath)
4. yaml.Unmarshal → []RuleYAML
5. Reject empty slice → error
6. convertYAMLToRule each entry (fail-fast on first error)
7. Return []*Rule
```

Errors from any step are wrapped with `fmt.Errorf("…: %w", err)` and include the resolved path and (where applicable) the 1-based rule index and ControlID for easy diagnosis.

---

## `LoadRulesFromConfigMap(ctx, clientset, configMapName, configMapNamespace, dataKey string) ([]*Rule, error)`

```
1. Validate configMapName, configMapNamespace, dataKey non-empty
2. Validate clientset != nil
3. clientset.CoreV1().ConfigMaps(ns).Get(ctx, name, metav1.GetOptions{})
4. Extract configMap.Data[dataKey] → yamlContent
5. Reject missing or empty key
6. yaml.Unmarshal([]byte(yamlContent)) → []RuleYAML
7. Reject empty slice
8. convertYAMLToRule each entry (fail-fast)
9. Return []*Rule
```

The `dataKey` parameter defaults to `"rules.yaml"` when set via `EngineConfig.ConfigMapDataKey`. Any key present in the ConfigMap's `data` map is valid.

---

## `convertYAMLToRule(ruleYAML *RuleYAML) (*Rule, error)`

Validates all required fields then constructs a `*Rule`:

| Validation | Error message |
|---|---|
| `ControlID == ""` | `"missing controlID in rule"` |
| `Title == ""` | `"missing title in rule <id>"` |
| `Severity == ""` | `"missing severity in rule <id>"` |
| `len(EventTypes) == 0` | `"missing eventTypes in rule <id>"` |
| `len(Conditions) == 0` | `"missing conditions in rule <id>"` |
| `Condition.Field == ""` | `"missing field in condition <n> of rule <id>"` |
| `Condition.Operator == ""` | `"missing operator in condition <n> of rule <id>"` |
| `Condition.Value == nil` | `"missing value in condition <n> of rule <id>"` |

No operator validation is performed here — an unknown operator will silently return `false` from `evaluateCondition` at match time.

---

## Key Anchor Comments

| Location | Anchor summary |
|---|---|
| `LoadRulesFromFile` | File-based rule loading with path resolution — Phase 3.1 Week 3 |
| `LoadRulesFromConfigMap` | ConfigMap-based rule loading via K8s API — Phase 3.2 Week 3 |
| `convertYAMLToRule` | YAML to Rule struct conversion with validation — Phase 3.1 Week 3 |

---

## Related Files

| File | Relationship |
|---|---|
| [engine.go](./engine.md) | `NewEngineWithConfig` calls both loader functions; `Rule`/`Condition` types defined here |
| `config/rules/cis-controls.yaml` | Example YAML file consumed by `LoadRulesFromFile` |
