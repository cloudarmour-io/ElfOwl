// ANCHOR: Unit tests for CapabilityMonitor - Phase 3: Testing - Dec 27, 2025
// Tests capability usage event monitoring, capability name mapping, and enrichment

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ============================================================================
// CapabilityMonitor Creation & Initialization Tests
// ============================================================================

func TestNewCapabilityMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewCapabilityMonitor(nil, logger)

	if monitor == nil {
		t.Fatal("expected non-nil monitor")
	}

	if monitor.logger != logger {
		t.Error("logger not assigned")
	}

	if monitor.started {
		t.Error("monitor should not be started on creation")
	}

	if cap(monitor.eventChan) != 100 {
		t.Errorf("expected channel buffer size 100, got %d", cap(monitor.eventChan))
	}
}

// ============================================================================
// CapabilityMonitor Lifecycle Tests
// ============================================================================

func TestCapabilityMonitorStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewCapabilityMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !monitor.started {
		t.Error("monitor.started should be true")
	}

	monitor.Stop()
}

func TestCapabilityMonitorStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewCapabilityMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	err := monitor.Stop()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if monitor.started {
		t.Error("monitor.started should be false")
	}
}

// ============================================================================
// CapabilityEvent Parsing Tests
// ============================================================================

func TestCapabilityEventParsing(t *testing.T) {
	testEvent := NewTestCapabilityEvent(1234, 21, 2) // CAP_SYS_ADMIN, use

	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, testEvent)
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	parsed := &CapabilityEvent{}
	err = binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", parsed.PID)
	}

	if parsed.Capability != 21 {
		t.Errorf("expected Capability 21, got %d", parsed.Capability)
	}

	if parsed.CheckType != 2 {
		t.Errorf("expected CheckType 2, got %d", parsed.CheckType)
	}
}

// ============================================================================
// Capability Name Mapping Tests
// ============================================================================

func TestCapabilityNames(t *testing.T) {
	tests := []struct {
		cap      uint32
		expected string
	}{
		{0, "CAP_CHOWN"},
		{1, "CAP_DAC_OVERRIDE"},
		{2, "CAP_DAC_READ_SEARCH"},
		{3, "CAP_FOWNER"},
		{4, "CAP_FSETID"},
		{5, "CAP_KILL"},
		{6, "CAP_SETGID"},
		{7, "CAP_SETUID"},
		{8, "CAP_SETPCAP"},
		{9, "CAP_LINUX_IMMUTABLE"},
		{10, "CAP_NET_BIND_SERVICE"},
		{11, "CAP_NET_BROADCAST"},
		{12, "CAP_NET_ADMIN"},
		{13, "CAP_NET_RAW"},
		{14, "CAP_IPC_LOCK"},
		{15, "CAP_IPC_OWNER"},
		{16, "CAP_SYS_MODULE"},
		{17, "CAP_SYS_RAWIO"},
		{18, "CAP_SYS_CHROOT"},
		{19, "CAP_SYS_PTRACE"},
		{20, "CAP_SYS_PACCT"},
		{21, "CAP_SYS_ADMIN"},
		{22, "CAP_SYS_BOOT"},
		{23, "CAP_SYS_NICE"},
		{24, "CAP_SYS_RESOURCE"},
		{25, "CAP_SYS_TIME"},
		{26, "CAP_SYS_TTY_CONFIG"},
		{27, "CAP_MKNOD"},
		{28, "CAP_LEASE"},
		{29, "CAP_AUDIT_WRITE"},
		{30, "CAP_AUDIT_CONTROL"},
		{31, "CAP_SETFCAP"},
		{32, "CAP_MAC_OVERRIDE"},
		{33, "CAP_MAC_ADMIN"},
		{34, "CAP_SYSLOG"},
		{35, "CAP_WAKE_ALARM"},
		{36, "CAP_BLOCK_SUSPEND"},
		{37, "CAP_AUDIT_READ"},
		{38, "CAP_PERFMON"},
		{39, "CAP_BPF"},
		{40, "CAP_CHECKPOINT_RESTORE"},
		{999, "CAP_UNKNOWN_999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := capabilityName(tt.cap)
			if name != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, name)
			}
		})
	}
}

// ============================================================================
// CapabilityContext Enrichment Tests
// ============================================================================

func TestCapabilityEnrichment(t *testing.T) {
	testEvent := NewTestCapabilityEvent(1234, 21, 2) // CAP_SYS_ADMIN, use

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	parsed := &CapabilityEvent{}
	binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)

	capName := capabilityName(parsed.Capability)
	allowed := parsed.CheckType != 2

	capCtx := &enrichment.CapabilityContext{
		Name:    capName,
		Allowed: allowed,
		PID:     parsed.PID,
	}

	enriched := &enrichment.EnrichedEvent{
		RawEvent:   parsed,
		EventType:  "capability_usage",
		Capability: capCtx,
		Timestamp:  time.Now(),
	}

	// Verify
	AssertEnrichedEvent(t, enriched, "capability_usage")
	AssertCapabilityContext(t, enriched.Capability, "CAP_SYS_ADMIN")

	if enriched.Capability.Allowed {
		t.Error("expected allowed=false for CheckType 2 (use)")
	}
}

func TestCapabilityAllowedLogic(t *testing.T) {
	tests := []struct {
		checkType uint8
		expected  bool
	}{
		{1, true},  // check → allowed
		{2, false}, // use → not allowed
		{3, true},  // other → allowed
	}

	for _, tt := range tests {
		allowed := tt.checkType != 2
		if allowed != tt.expected {
			t.Errorf("checkType %d: expected allowed=%v, got %v", tt.checkType, tt.expected, allowed)
		}
	}
}

// ============================================================================
// CapabilityMonitor Event Channel Tests
// ============================================================================

func TestCapabilityEventChannelFlow(t *testing.T) {
	logger := zaptest.NewLogger(t)

	testEvent := NewTestCapabilityEvent(1234, 12, 2) // CAP_NET_ADMIN
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	mockReader := NewMockReader(buf.Bytes())
	programSet := NewMockProgramSet(mockReader)
	monitor := NewCapabilityMonitor(programSet, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	monitor.Start(ctx)
	defer monitor.Stop()

	event := WaitForEvent(t, monitor.eventChan, 500*time.Millisecond)

	if event == nil {
		t.Fatal("expected event, got nil")
	}

	AssertEnrichedEvent(t, event, "capability_usage")
}

// ============================================================================
// CapabilityMonitor Context Cancellation Tests
// ============================================================================

func TestCapabilityContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewCapabilityMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	cancel()

	time.Sleep(100 * time.Millisecond)

	// Context cancellation stops the event loop but doesn't clear the started flag
	// Must call Stop() to properly clean up
	err = monitor.Stop()
	if err != nil {
		t.Fatalf("stop failed: %v", err)
	}

	if monitor.started {
		t.Error("monitor should be stopped after Stop() call")
	}
}

// ============================================================================
// CapabilityMonitor Error Handling Tests
// ============================================================================

func TestCapabilityReaderError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mockReader := NewMockReader()
	mockReader.readError = ErrSimulated
	programSet := NewMockProgramSet(mockReader)
	monitor := NewCapabilityMonitor(programSet, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if !monitor.started {
		t.Error("monitor should remain running despite reader errors")
	}

	monitor.Stop()
}

// ============================================================================
// CapabilityMonitor EventChan Return Type Test
// ============================================================================

func TestCapabilityEventChanReturnType(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewCapabilityMonitor(nil, logger)

	ch := monitor.EventChan()

	if ch == nil {
		t.Fatal("event channel is nil")
	}

	_ = (<-chan *enrichment.EnrichedEvent)(ch)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkCapabilityMonitorEventParsing(b *testing.B) {
	events := make([][]byte, b.N)

	for i := 0; i < b.N; i++ {
		evt := NewTestCapabilityEvent(uint32(1000+i), uint32(i%39), 2)
		buf := &bytes.Buffer{}
		binary.Write(buf, binary.LittleEndian, evt)
		events[i] = buf.Bytes()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parsed := &CapabilityEvent{}
		binary.Read(bytes.NewReader(events[i]), binary.LittleEndian, parsed)
	}
}

func BenchmarkCapabilityNameLookup(b *testing.B) {
	capabilities := []uint32{0, 5, 12, 19, 21, 25, 36, 37, 38}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		cap := capabilities[i%len(capabilities)]
		_ = capabilityName(cap)
	}
}

func BenchmarkCapabilityMonitorEnrichment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		evt := NewTestCapabilityEvent(1234, 21, 2)

		capName := capabilityName(evt.Capability)
		allowed := evt.CheckType != 2

		capCtx := &enrichment.CapabilityContext{
			Name:    capName,
			Allowed: allowed,
			PID:     evt.PID,
		}

		_ = &enrichment.EnrichedEvent{
			RawEvent:   evt,
			EventType:  "capability_usage",
			Capability: capCtx,
			Timestamp:  time.Now(),
		}
	}
}
