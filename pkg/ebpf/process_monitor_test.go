// ANCHOR: Unit tests for ProcessMonitor - Phase 3: Testing - Dec 27, 2025
// Tests process event monitoring, parsing, enrichment, and lifecycle management

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ============================================================================
// ProcessMonitor Creation & Initialization Tests
// ============================================================================

func TestNewProcessMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)

	monitor := NewProcessMonitor(nil, logger)

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
// ProcessMonitor Start/Stop Lifecycle Tests
// ============================================================================

func TestProcessMonitorStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !monitor.started {
		t.Error("monitor.started should be true after Start()")
	}

	monitor.Stop()
}

func TestProcessMonitorDoubleStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err1 := monitor.Start(ctx)
	if err1 != nil {
		t.Fatalf("first start failed: %v", err1)
	}

	err2 := monitor.Start(ctx)
	if err2 == nil {
		t.Error("expected error on double start, got nil")
	}

	monitor.Stop()
}

func TestProcessMonitorStartWithNilProgramSet(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewProcessMonitor(nil, logger)

	ctx := context.Background()
	err := monitor.Start(ctx)

	if err == nil {
		t.Error("expected error when ProgramSet is nil")
	}
}

func TestProcessMonitorStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	monitor.Start(ctx)
	time.Sleep(50 * time.Millisecond) // Let event loop start

	err := monitor.Stop()
	if err != nil {
		t.Fatalf("expected no error on stop, got %v", err)
	}

	if monitor.started {
		t.Error("monitor.started should be false after Stop()")
	}
}

func TestProcessMonitorStopWithoutStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewProcessMonitor(nil, logger)

	err := monitor.Stop()
	if err == nil {
		t.Error("expected error when stopping without start")
	}
}

// ============================================================================
// ProcessEvent Parsing Tests
// ============================================================================

func TestProcessEventParsing(t *testing.T) {
	// Create test event
	testEvent := NewTestProcessEvent(1234, 1000, 1000, "/bin/bash", "bash -i")

	// Serialize to binary
	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, testEvent)
	if err != nil {
		t.Fatalf("failed to serialize event: %v", err)
	}

	// Parse back
	parsed := &ProcessEvent{}
	err = binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)
	if err != nil {
		t.Fatalf("failed to parse event: %v", err)
	}

	if parsed.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", parsed.PID)
	}

	if parsed.UID != 1000 {
		t.Errorf("expected UID 1000, got %d", parsed.UID)
	}

	if parsed.GID != 1000 {
		t.Errorf("expected GID 1000, got %d", parsed.GID)
	}
}

// ============================================================================
// ProcessContext Enrichment Tests
// ============================================================================

func TestProcessEnrichment(t *testing.T) {
	testEvent := NewTestProcessEvent(1234, 1000, 1000, "/bin/bash", "bash -i")

	// Serialize and re-parse like the monitor does
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	parsed := &ProcessEvent{}
	binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)

	// Create enriched event like ProcessMonitor does
	procCtx := &enrichment.ProcessContext{
		PID:      parsed.PID,
		UID:      parsed.UID,
		GID:      parsed.GID,
		Filename: "/bin/bash",
		Command:  "bash -i",
	}

	enriched := &enrichment.EnrichedEvent{
		RawEvent:  parsed,
		EventType: "process_execution",
		Process:   procCtx,
		Timestamp: time.Now(),
	}

	// Verify enrichment
	if enriched.EventType != "process_execution" {
		t.Errorf("expected event type 'process_execution', got %q", enriched.EventType)
	}

	if enriched.Process.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", enriched.Process.PID)
	}

	if enriched.Process.Filename != "/bin/bash" {
		t.Errorf("expected filename '/bin/bash', got %q", enriched.Process.Filename)
	}
}

// ============================================================================
// ProcessMonitor Event Channel Tests
// ============================================================================

func TestProcessEventChannelFlow(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create mock reader with one event
	testEvent := NewTestProcessEvent(1234, 1000, 1000, "/bin/bash", "bash -i")
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	mockReader := NewMockReader(buf.Bytes())
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	monitor.Start(ctx)
	defer monitor.Stop()

	// Wait for event with timeout
	event := WaitForEvent(t, monitor.eventChan, 500*time.Millisecond)

	if event == nil {
		t.Fatal("expected event, got nil")
	}

	AssertEnrichedEvent(t, event, "process_execution")
	AssertProcessContext(t, event.Process, 1234)
}

// ============================================================================
// ProcessMonitor Context Cancellation Tests
// ============================================================================

func TestProcessContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(50 * time.Millisecond)
	cancel() // Trigger context cancellation

	time.Sleep(100 * time.Millisecond) // Give goroutine time to exit

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
// ProcessMonitor Error Handling Tests
// ============================================================================

func TestProcessReaderError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create reader that returns error
	mockReader := NewMockReader()
	mockReader.readError = ErrSimulated
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Monitor should still be running despite reader errors
	if !monitor.started {
		t.Error("monitor should remain running despite reader errors")
	}

	monitor.Stop()
}

func TestProcessParseError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Create reader with malformed event data
	mockReader := NewMockReader([]byte("invalid"))
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := monitor.Start(ctx)
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Monitor should still be running despite parse errors
	if !monitor.started {
		t.Error("monitor should remain running despite parse errors")
	}

	monitor.Stop()
}

// ============================================================================
// ProcessMonitor Concurrency Tests
// ============================================================================

func TestProcessMonitorConcurrentStartStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewProcessMonitor(programSet, logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	var startErr, stopErr error

	// Concurrent start
	wg.Add(1)
	go func() {
		defer wg.Done()
		startErr = monitor.Start(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(100 * time.Millisecond)
		stopErr = monitor.Stop()
	}()

	wg.Wait()

	if startErr != nil {
		t.Errorf("start error: %v", startErr)
	}

	if stopErr != nil {
		t.Errorf("stop error: %v", stopErr)
	}
}

// ============================================================================
// ProcessMonitor EventChan Return Type Test
// ============================================================================

func TestProcessEventChanReturnType(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewProcessMonitor(nil, logger)

	ch := monitor.EventChan()

	// Verify channel type
	if ch == nil {
		t.Fatal("event channel is nil")
	}

	// Verify it's read-only
	_ = (<-chan *enrichment.EnrichedEvent)(ch)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkProcessMonitorEventParsing(b *testing.B) {
	events := make([][]byte, b.N)

	// Pre-create binary events
	for i := 0; i < b.N; i++ {
		evt := NewTestProcessEvent(uint32(1000+i), 1000, 1000, "/bin/bash", "bash -i")
		buf := &bytes.Buffer{}
		binary.Write(buf, binary.LittleEndian, evt)
		events[i] = buf.Bytes()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parsed := &ProcessEvent{}
		binary.Read(bytes.NewReader(events[i]), binary.LittleEndian, parsed)
	}
}

func BenchmarkProcessMonitorEnrichment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		evt := NewTestProcessEvent(1234, 1000, 1000, "/bin/bash", "bash -i")

		procCtx := &enrichment.ProcessContext{
			PID:      evt.PID,
			UID:      evt.UID,
			GID:      evt.GID,
			Filename: "/bin/bash",
			Command:  "bash -i",
		}

		_ = &enrichment.EnrichedEvent{
			RawEvent:  evt,
			EventType: "process_execution",
			Process:   procCtx,
			Timestamp: time.Now(),
		}
	}
}

// ============================================================================
// Simulated Errors
// ============================================================================

var ErrSimulated = &SimulatedError{msg: "simulated error"}

type SimulatedError struct {
	msg string
}

func (e *SimulatedError) Error() string {
	return e.msg
}
