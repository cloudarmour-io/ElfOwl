package agent

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/udyansh/elf-owl/pkg/rules"
	"go.uber.org/zap"
)

func TestWatchRuleUpdatesReloadsOnSignatureChange(t *testing.T) {
	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	writeRuleFile(t, rulesPath, "TEST_RULE_A")

	engine, err := rules.NewEngineWithConfig(&rules.EngineConfig{RuleFilePath: rulesPath})
	if err != nil {
		t.Fatalf("failed to build initial rule engine: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Agent.Rules.FilePath = rulesPath
	cfg.Agent.Rules.ConfigMap.Name = ""
	cfg.Agent.Rules.ConfigMap.Namespace = ""

	agent := &Agent{
		Config:             cfg,
		Logger:             zap.NewNop(),
		RuleEngine:         engine,
		done:               make(chan struct{}),
		ruleReloadInterval: 25 * time.Millisecond,
		ruleReloadTimeout:  250 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.watchRuleUpdates(ctx)
	defer close(agent.done)

	initialSig := ruleEngineSignature(agent.getRuleEngine())
	writeRuleFile(t, rulesPath, "TEST_RULE_B")

	if !waitUntil(2*time.Second, 20*time.Millisecond, func() bool {
		return ruleEngineSignature(agent.getRuleEngine()) != initialSig
	}) {
		t.Fatalf("expected watcher to reload engine when rule file signature changes")
	}
}

func TestWatchRuleUpdatesKeepsExistingEngineOnReloadFailure(t *testing.T) {
	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	writeRuleFile(t, rulesPath, "TEST_RULE_VALID")

	engine, err := rules.NewEngineWithConfig(&rules.EngineConfig{RuleFilePath: rulesPath})
	if err != nil {
		t.Fatalf("failed to build initial rule engine: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Agent.Rules.FilePath = rulesPath
	cfg.Agent.Rules.ConfigMap.Name = ""
	cfg.Agent.Rules.ConfigMap.Namespace = ""

	agent := &Agent{
		Config:             cfg,
		Logger:             zap.NewNop(),
		RuleEngine:         engine,
		done:               make(chan struct{}),
		ruleReloadInterval: 25 * time.Millisecond,
		ruleReloadTimeout:  250 * time.Millisecond,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go agent.watchRuleUpdates(ctx)
	defer close(agent.done)

	initialSig := ruleEngineSignature(agent.getRuleEngine())
	if err := os.WriteFile(rulesPath, []byte("- invalid: ["), 0600); err != nil {
		t.Fatalf("failed to write invalid rule file: %v", err)
	}

	time.Sleep(250 * time.Millisecond)
	if got := ruleEngineSignature(agent.getRuleEngine()); got != initialSig {
		t.Fatalf("expected watcher to keep existing engine on reload failure")
	}
}

func TestRuleReloadTimingFallbacks(t *testing.T) {
	a := &Agent{}
	if got := a.effectiveRuleReloadInterval(); got != ruleReloadInterval {
		t.Fatalf("expected default interval %v, got %v", ruleReloadInterval, got)
	}
	if got := a.effectiveRuleReloadTimeout(); got != ruleReloadTimeout {
		t.Fatalf("expected default timeout %v, got %v", ruleReloadTimeout, got)
	}

	a.ruleReloadInterval = 5 * time.Second
	a.ruleReloadTimeout = 15 * time.Second
	if got := a.effectiveRuleReloadInterval(); got != 5*time.Second {
		t.Fatalf("expected configured interval to be used, got %v", got)
	}
	if got := a.effectiveRuleReloadTimeout(); got != 15*time.Second {
		t.Fatalf("expected configured timeout to be used, got %v", got)
	}
}

func writeRuleFile(t *testing.T, path, controlID string) {
	t.Helper()
	content := "- controlID: " + controlID + "\n" +
		"  title: Test Rule\n" +
		"  severity: HIGH\n" +
		"  eventTypes:\n" +
		"    - process_execution\n" +
		"  conditions:\n" +
		"    - field: process.uid\n" +
		"      operator: equals\n" +
		"      value: 0\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write rule file %s: %v", path, err)
	}
}

func waitUntil(timeout, step time.Duration, condition func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return true
		}
		time.Sleep(step)
	}
	return condition()
}
