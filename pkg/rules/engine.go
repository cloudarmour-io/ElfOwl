// ANCHOR: CIS control rule matching engine - Dec 26, 2025
// Matches enriched events against CIS Kubernetes v1.8 control rules
// IMPLEMENTATION IN PROGRESS - Week 2 task

package rules

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// Engine matches enriched events against CIS control rules
type Engine struct {
	Rules  []*Rule
	Logger *zap.Logger
}

// Rule defines a CIS control detection rule
type Rule struct {
	ControlID  string
	Title      string
	Severity   string
	EventTypes []string
	Conditions []Condition
}

// Condition is a single matching criterion
type Condition struct {
	Field    string
	Operator string
	Value    interface{}
}

// Violation represents a detected CIS violation
type Violation struct {
	ControlID      string
	Title          string
	Severity       string
	Timestamp      time.Time
	Pod            *enrichment.K8sContext
	Container      *enrichment.ContainerContext
	Description    string
	RemediationRef string
}

// NewEngine creates a new rule engine
// ANCHOR: Rule engine initialization without config dependency - Dec 26, 2025
// Removed config parameter to break circular import dependency
func NewEngine() (*Engine, error) {
	logger, _ := zap.NewProduction()

	engine := &Engine{
		Rules:  loadCISRules(),
		Logger: logger,
	}

	return engine, nil
}

// Match evaluates an enriched event against all rules
func (e *Engine) Match(event *enrichment.EnrichedEvent) []*Violation {
	var violations []*Violation

	for _, rule := range e.Rules {
		// Check if rule applies to this event type
		if !contains(rule.EventTypes, event.EventType) {
			continue
		}

		// Evaluate all conditions
		allMatch := true
		for _, cond := range rule.Conditions {
			if !e.evaluateCondition(event, cond) {
				allMatch = false
				break
			}
		}

		if allMatch {
			violations = append(violations, &Violation{
				ControlID:      rule.ControlID,
				Title:          rule.Title,
				Severity:       rule.Severity,
				Timestamp:      time.Now(),
				Pod:            event.Kubernetes,
				Container:      event.Container,
				Description:    fmt.Sprintf("%s: %s", rule.ControlID, rule.Title),
				RemediationRef: fmt.Sprintf("docs/remediation#%s", rule.ControlID),
			})
		}
	}

	return violations
}

// evaluateCondition evaluates a single condition against an event
func (e *Engine) evaluateCondition(event *enrichment.EnrichedEvent, cond Condition) bool {
	// ANCHOR: Condition evaluation for CIS rule matching - Dec 26, 2025
	// Implements field extraction and operator-based matching
	// Supports: equals, not_equals, contains, in, regex patterns

	// Extract field value from event
	fieldValue := e.extractField(event, cond.Field)
	if fieldValue == nil {
		return false
	}

	// Evaluate based on operator
	switch cond.Operator {
	case "equals", "==":
		return reflect.DeepEqual(fieldValue, cond.Value)

	case "not_equals", "!=":
		return !reflect.DeepEqual(fieldValue, cond.Value)

	case "contains":
		// String contains check
		if str, ok := fieldValue.(string); ok {
			if val, ok := cond.Value.(string); ok {
				return strings.Contains(str, val)
			}
		}
		return false

	case "in":
		return valueInSlice(cond.Value, fieldValue)

	case "greater_than":
		fv, fOk := toFloat(fieldValue)
		cv, cOk := toFloat(cond.Value)
		return fOk && cOk && fv > cv

	case "less_than":
		fv, fOk := toFloat(fieldValue)
		cv, cOk := toFloat(cond.Value)
		return fOk && cOk && fv < cv

	default:
		e.Logger.Warn("unknown operator", zap.String("operator", cond.Operator))
		return false
	}
}

// extractField extracts a field value from an enriched event
// Supports nested fields like "kubernetes.pod_name", "container.id"
// ANCHOR: Field extraction for rule matching - Dec 26, 2025
// Only includes fields that exist in enrichment.EnrichedEvent structure
// Extended fields (process, network) will be added in Week 2 implementation
func (e *Engine) extractField(event *enrichment.EnrichedEvent, fieldPath string) interface{} {
	if event == nil {
		return nil
	}

	switch fieldPath {
	// Event fields
	case "event_type":
		return event.EventType
	case "timestamp":
		return event.Timestamp
	case "severity":
		return event.Severity
	case "cis_control":
		return event.CISControl

	// Kubernetes context fields
	case "kubernetes.namespace":
		if event.Kubernetes != nil {
			return event.Kubernetes.Namespace
		}
	case "kubernetes.pod_name":
		if event.Kubernetes != nil {
			return event.Kubernetes.PodName
		}
	case "kubernetes.pod_uid":
		if event.Kubernetes != nil {
			return event.Kubernetes.PodUID
		}
	case "kubernetes.cluster_id":
		if event.Kubernetes != nil {
			return event.Kubernetes.ClusterID
		}
	case "kubernetes.node_name":
		if event.Kubernetes != nil {
			return event.Kubernetes.NodeName
		}
	case "kubernetes.service_account":
		if event.Kubernetes != nil {
			return event.Kubernetes.ServiceAccount
		}
	case "kubernetes.has_default_deny_policy":
		if event.Kubernetes != nil {
			return event.Kubernetes.HasDefaultDenyNetworkPolicy
		}

	// Container context fields
	case "container.id":
		if event.Container != nil {
			return event.Container.ContainerID
		}
	case "container.name":
		if event.Container != nil {
			return event.Container.ContainerName
		}
	case "container.runtime":
		if event.Container != nil {
			return event.Container.Runtime
		}
	case "container.security_context.privileged":
		if event.Container != nil {
			return event.Container.Privileged
		}
	case "container.run_as_root":
		if event.Container != nil {
			return event.Container.RunAsRoot
		}

	// Process fields
	case "process.uid":
		if event.Process != nil {
			return int(event.Process.UID)
		}
	case "process.pid":
		if event.Process != nil {
			return int(event.Process.PID)
		}
	case "process.command":
		if event.Process != nil {
			return event.Process.Command
		}

	// File fields
	case "file.path":
		if event.File != nil {
			return event.File.Path
		}
	case "file.operation":
		if event.File != nil {
			return event.File.Operation
		}

	// Capability fields
	case "capability.name":
		if event.Capability != nil {
			return event.Capability.Name
		}
	case "capability.allowed":
		if event.Capability != nil {
			return event.Capability.Allowed
		}

	default:
		return nil
	}

	return nil
}

// valueInSlice checks if fieldValue is contained within slice-like condValue
func valueInSlice(condValue interface{}, fieldValue interface{}) bool {
	val := reflect.ValueOf(condValue)
	if val.Kind() != reflect.Slice && val.Kind() != reflect.Array {
		return false
	}

	for i := 0; i < val.Len(); i++ {
		if reflect.DeepEqual(val.Index(i).Interface(), fieldValue) {
			return true
		}
	}

	return false
}

// toFloat converts ints uints etc. to float64 for comparisons
func toFloat(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

// loadCISRules loads all CIS Kubernetes v1.8 control rules
// ANCHOR: Load stub CIS rules from cis_mappings.go - Dec 26, 2025
// Returns the 6 automated stub controls defined in CISControls variable.
// Full implementation with 48 total automated controls planned for Week 2.
func loadCISRules() []*Rule {
	return CISControls
}
