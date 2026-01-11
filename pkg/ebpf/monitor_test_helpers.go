// ANCHOR: Shared test utilities for eBPF monitors - Phase 3: Testing - Dec 27, 2025
// Provides mock readers, event factories, and assertion helpers for monitor tests

package ebpf

import (
	"fmt"
	"testing"
	"time"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ============================================================================
// Mock Reader Implementation
// ============================================================================

// MockReader simulates reading events from kernel for testing
type MockReader struct {
	data      [][]byte // Queue of event data to return
	readCount int
	readError error
	closeErr  error
}

// NewMockReader creates a mock reader with predefined data
func NewMockReader(events ...[]byte) *MockReader {
	return &MockReader{
		data: events,
	}
}

// Read returns next event data or error
func (mr *MockReader) Read() ([]byte, error) {
	if mr.readError != nil {
		return nil, mr.readError
	}

	if mr.readCount >= len(mr.data) {
		// Return empty to simulate no data available
		return nil, nil
	}

	data := mr.data[mr.readCount]
	mr.readCount++
	return data, nil
}

// Close implements Reader interface
func (mr *MockReader) Close() error {
	return mr.closeErr
}

// ============================================================================
// Mock ProgramSet Implementation
// ============================================================================

// NewMockProgramSet creates a ProgramSet with a mock reader for testing
func NewMockProgramSet(reader Reader) *ProgramSet {
	return &ProgramSet{
		Reader: reader,
		Logger: nil, // Will be set by caller if needed
	}
}

// ============================================================================
// Event Factories - Create test events
// ============================================================================

// NewTestProcessEvent creates a test ProcessEvent
func NewTestProcessEvent(pid, uid, gid uint32, filename, argv string) *ProcessEvent {
	evt := &ProcessEvent{
		PID:           pid,
		UID:           uid,
		GID:           gid,
		Capabilities:  0,
		CgroupID:      1,
	}
	copy(evt.Filename[:], filename)
	copy(evt.Argv[:], argv)
	return evt
}

// NewTestNetworkEvent creates a test NetworkEvent
func NewTestNetworkEvent(pid uint32, srcIP, dstIP string, srcPort, dstPort uint16, protocol uint8) *NetworkEvent {
	// Parse simple IPv4 strings (e.g., "192.168.1.1")
	saddr := ipStringToUint32(srcIP)
	daddr := ipStringToUint32(dstIP)

	return &NetworkEvent{
		PID:      pid,
		Family:   2, // AF_INET
		SPort:    srcPort,
		DPort:    dstPort,
		SAddr:    saddr,
		DAddr:    daddr,
		Protocol: protocol,
		CgroupID: 1,
	}
}

// NewTestFileEvent creates a test FileEvent
func NewTestFileEvent(pid uint32, operation uint8, filename string) *FileEvent {
	evt := &FileEvent{
		PID:       pid,
		Flags:     0,
		Operation: operation,
		CgroupID:  1,
	}
	copy(evt.Filename[:], filename)
	return evt
}

// NewTestCapabilityEvent creates a test CapabilityEvent
func NewTestCapabilityEvent(pid uint32, capability uint32, checkType uint8) *CapabilityEvent {
	return &CapabilityEvent{
		PID:        pid,
		Capability: capability,
		CheckType:  checkType,
		CgroupID:   1,
	}
}

// NewTestDNSEvent creates a test DNSEvent
func NewTestDNSEvent(pid uint32, domain string, queryType uint16, responseCode uint8, allowed uint8) *DNSEvent {
	evt := &DNSEvent{
		PID:          pid,
		QueryType:    queryType,
		ResponseCode: responseCode,
		QueryAllowed: allowed,
		CgroupID:     1,
	}
	copy(evt.QueryName[:], domain)
	return evt
}

// ============================================================================
// Helper Functions
// ============================================================================

// ipStringToUint32 converts simple IPv4 string (e.g., "192.168.1.1") to uint32
func ipStringToUint32(ip string) uint32 {
	var octets [4]uint8
	fmt.Sscanf(ip, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3])
	return uint32(octets[0]) | (uint32(octets[1]) << 8) | (uint32(octets[2]) << 16) | (uint32(octets[3]) << 24)
}

// ============================================================================
// Assertion Helpers
// ============================================================================

// AssertEnrichedEvent verifies an EnrichedEvent has expected fields
func AssertEnrichedEvent(t *testing.T, event *enrichment.EnrichedEvent, expectedType string) {
	t.Helper()

	if event == nil {
		t.Fatal("enriched event is nil")
	}

	if event.EventType != expectedType {
		t.Errorf("expected event type %q, got %q", expectedType, event.EventType)
	}

	if event.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}

	if event.RawEvent == nil {
		t.Error("raw event should not be nil")
	}
}

// AssertProcessContext verifies a ProcessContext has expected fields
func AssertProcessContext(t *testing.T, ctx *enrichment.ProcessContext, expectedPID uint32) {
	t.Helper()

	if ctx == nil {
		t.Fatal("process context is nil")
	}

	if ctx.PID != expectedPID {
		t.Errorf("expected PID %d, got %d", expectedPID, ctx.PID)
	}

	if ctx.Filename == "" {
		t.Error("filename should not be empty")
	}
}

// AssertNetworkContext verifies a NetworkContext has expected fields
func AssertNetworkContext(t *testing.T, ctx *enrichment.NetworkContext, expectedProtocol string) {
	t.Helper()

	if ctx == nil {
		t.Fatal("network context is nil")
	}

	if ctx.Protocol != expectedProtocol {
		t.Errorf("expected protocol %q, got %q", expectedProtocol, ctx.Protocol)
	}

	if ctx.SourceIP == "" || ctx.DestinationIP == "" {
		t.Error("IP addresses should not be empty")
	}

	if ctx.SourcePort == 0 || ctx.DestinationPort == 0 {
		t.Error("ports should not be zero")
	}
}

// AssertFileContext verifies a FileContext has expected fields
func AssertFileContext(t *testing.T, ctx *enrichment.FileContext, expectedPath string) {
	t.Helper()

	if ctx == nil {
		t.Fatal("file context is nil")
	}

	if ctx.Path != expectedPath {
		t.Errorf("expected path %q, got %q", expectedPath, ctx.Path)
	}

	if ctx.Operation == "" {
		t.Error("operation should not be empty")
	}
}

// AssertCapabilityContext verifies a CapabilityContext has expected fields
func AssertCapabilityContext(t *testing.T, ctx *enrichment.CapabilityContext, expectedName string) {
	t.Helper()

	if ctx == nil {
		t.Fatal("capability context is nil")
	}

	if ctx.Name != expectedName {
		t.Errorf("expected capability %q, got %q", expectedName, ctx.Name)
	}
}

// AssertDNSContext verifies a DNSContext has expected fields
func AssertDNSContext(t *testing.T, ctx *enrichment.DNSContext, expectedDomain string) {
	t.Helper()

	if ctx == nil {
		t.Fatal("dns context is nil")
	}

	if ctx.QueryName != expectedDomain {
		t.Errorf("expected domain %q, got %q", expectedDomain, ctx.QueryName)
	}

	if ctx.QueryType == "" {
		t.Error("query type should not be empty")
	}
}

// ============================================================================
// Benchmark Helpers
// ============================================================================

// BenchmarkEventFactory measures event factory performance
func BenchmarkEventFactory(b *testing.B) {
	b.Run("ProcessEvent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewTestProcessEvent(1000, 1000, 1000, "/bin/bash", "bash -i")
		}
	})

	b.Run("NetworkEvent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewTestNetworkEvent(1000, "192.168.1.1", "8.8.8.8", 12345, 53, 6)
		}
	})

	b.Run("FileEvent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewTestFileEvent(1000, 1, "/etc/passwd")
		}
	})

	b.Run("CapabilityEvent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewTestCapabilityEvent(1000, 19, 2)
		}
	})

	b.Run("DNSEvent", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = NewTestDNSEvent(1000, "example.com", 1, 0, 1)
		}
	})
}

// WaitForEvent waits for an event on a channel with timeout
func WaitForEvent(t *testing.T, ch <-chan *enrichment.EnrichedEvent, timeout time.Duration) *enrichment.EnrichedEvent {
	t.Helper()

	select {
	case event := <-ch:
		return event
	case <-time.After(timeout):
		t.Fatal("timeout waiting for event")
		return nil
	}
}

// DrainChannel reads all available events from a channel without blocking
func DrainChannel(ch <-chan *enrichment.EnrichedEvent) int {
	count := 0
	for {
		select {
		case <-ch:
			count++
		default:
			return count
		}
	}
}
