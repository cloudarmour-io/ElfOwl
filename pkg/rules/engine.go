// ANCHOR: CIS control rule matching engine - Dec 26, 2025
// Matches enriched events against CIS Kubernetes v1.8 control rules
// IMPLEMENTATION IN PROGRESS - Week 2 task

package rules

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/agent"
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
func NewEngine(config *agent.Config) (*Engine, error) {
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
	// TODO: Week 2 implementation
	// For now, return false (no violations detected)
	return false
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
func loadCISRules() []*Rule {
	// TODO: Week 2 implementation - Load from loadCISRules() in cis_mappings.go
	return []*Rule{}
}
