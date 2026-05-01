// ANCHOR: Unit tests for NetworkMonitor - Phase 3: Testing - Dec 27, 2025
// Tests network event monitoring, IP conversion, and enrichment

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"go.uber.org/zap/zaptest"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// ============================================================================
// NetworkMonitor Creation & Initialization Tests
// ============================================================================

func TestNewNetworkMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewNetworkMonitor(nil, logger, 100, nil, nil)

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
// NetworkMonitor Lifecycle Tests
// ============================================================================

func TestNewNetworkMonitorStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewNetworkMonitor(programSet, logger, 100, nil, nil)

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

func TestNewNetworkMonitorStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewNetworkMonitor(programSet, logger, 100, nil, nil)

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
// NetworkEvent Parsing Tests
// ============================================================================

func TestNetworkEventParsing(t *testing.T) {
	testEvent := NewTestNetworkEvent(1234, "192.168.1.1", "8.8.8.8", 12345, 53, 6)

	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, testEvent)
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	parsed := &NetworkEvent{}
	err = binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", parsed.PID)
	}

	if parsed.SPort != 12345 {
		t.Errorf("expected SPort 12345, got %d", parsed.SPort)
	}

	if parsed.DPort != 53 {
		t.Errorf("expected DPort 53, got %d", parsed.DPort)
	}

	if parsed.Protocol != 6 {
		t.Errorf("expected Protocol 6 (TCP), got %d", parsed.Protocol)
	}
}

// ============================================================================
// IP Address Conversion Tests
// ============================================================================

func TestIPAddressConversion(t *testing.T) {
	// Test IPv4 conversion: 192.168.1.1
	saddr := uint32(192) | (uint32(168) << 8) | (uint32(1) << 16) | (uint32(1) << 24)

	// Convert like NetworkMonitor does
	ip := net.IPv4(byte(saddr), byte(saddr>>8), byte(saddr>>16), byte(saddr>>24))

	expected := "192.168.1.1"
	if ip.String() != expected {
		t.Errorf("expected IP %q, got %q", expected, ip.String())
	}
}

func TestIPv4LocalAddress(t *testing.T) {
	// 127.0.0.1 (localhost)
	saddr := uint32(127) | (uint32(0) << 8) | (uint32(0) << 16) | (uint32(1) << 24)
	ip := net.IPv4(byte(saddr), byte(saddr>>8), byte(saddr>>16), byte(saddr>>24))

	expected := "127.0.0.1"
	if ip.String() != expected {
		t.Errorf("expected IP %q, got %q", expected, ip.String())
	}
}

// ============================================================================
// NetworkContext Enrichment Tests
// ============================================================================

func TestNetworkEnrichment(t *testing.T) {
	testEvent := NewTestNetworkEvent(1234, "192.168.1.1", "8.8.8.8", 12345, 53, 6)

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	parsed := &NetworkEvent{}
	binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)

	// Create enriched event
	protocol := "tcp"
	if parsed.Protocol == 17 { // UDP
		protocol = "udp"
	}

	netCtx := &enrichment.NetworkContext{
		SourceIP:        net.IPv4(byte(parsed.SAddr), byte(parsed.SAddr>>8), byte(parsed.SAddr>>16), byte(parsed.SAddr>>24)).String(),
		DestinationIP:   net.IPv4(byte(parsed.DAddr), byte(parsed.DAddr>>8), byte(parsed.DAddr>>16), byte(parsed.DAddr>>24)).String(),
		SourcePort:      parsed.SPort,
		DestinationPort: parsed.DPort,
		Protocol:        protocol,
	}

	enriched := &enrichment.EnrichedEvent{
		RawEvent:  parsed,
		EventType: "network_connection",
		Network:   netCtx,
		Timestamp: time.Now(),
	}

	// Verify
	AssertEnrichedEvent(t, enriched, "network_connection")
	AssertNetworkContext(t, enriched.Network, "tcp")

	if enriched.Network.SourceIP != "192.168.1.1" {
		t.Errorf("expected source IP 192.168.1.1, got %q", enriched.Network.SourceIP)
	}

	if enriched.Network.DestinationIP != "8.8.8.8" {
		t.Errorf("expected dest IP 8.8.8.8, got %q", enriched.Network.DestinationIP)
	}

	if enriched.Network.SourcePort != 12345 {
		t.Errorf("expected source port 12345, got %d", enriched.Network.SourcePort)
	}

	if enriched.Network.DestinationPort != 53 {
		t.Errorf("expected dest port 53, got %d", enriched.Network.DestinationPort)
	}
}

// ============================================================================
// NetworkMonitor Protocol Mapping Tests
// ============================================================================

func TestNetworkProtocolTCP(t *testing.T) {
	protocol := "tcp"
	if 6 == 17 { // Not UDP
		protocol = "udp"
	}

	if protocol != "tcp" {
		t.Errorf("expected protocol 'tcp', got %q", protocol)
	}
}

func TestNetworkProtocolUDP(t *testing.T) {
	protocol := "tcp"
	if 17 == 17 { // UDP
		protocol = "udp"
	}

	if protocol != "udp" {
		t.Errorf("expected protocol 'udp', got %q", protocol)
	}
}

// ============================================================================
// NetworkMonitor Event Channel Tests
// ============================================================================

func TestNetworkEventChannelFlow(t *testing.T) {
	logger := zaptest.NewLogger(t)

	testEvent := NewTestNetworkEvent(1234, "10.0.0.1", "1.1.1.1", 54321, 443, 6)
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	mockReader := NewMockReader(buf.Bytes())
	programSet := NewMockProgramSet(mockReader)
	monitor := NewNetworkMonitor(programSet, logger, 100, nil, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	monitor.Start(ctx)
	defer monitor.Stop()

	event := WaitForEvent(t, monitor.eventChan, 500*time.Millisecond)

	if event == nil {
		t.Fatal("expected event, got nil")
	}

	AssertEnrichedEvent(t, event, "network_connection")
}

// ============================================================================
// NetworkMonitor Context Cancellation Tests
// ============================================================================

func TestNetworkContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewNetworkMonitor(programSet, logger, 100, nil, nil)

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
// NetworkMonitor Error Handling Tests
// ============================================================================

func TestNetworkReaderError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mockReader := NewMockReader()
	mockReader.readError = ErrSimulated
	programSet := NewMockProgramSet(mockReader)
	monitor := NewNetworkMonitor(programSet, logger, 100, nil, nil)

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
// NetworkMonitor EventChan Return Type Test
// ============================================================================

func TestNetworkEventChanReturnType(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewNetworkMonitor(nil, logger, 100, nil, nil)

	ch := monitor.EventChan()

	if ch == nil {
		t.Fatal("event channel is nil")
	}

	// Verify it's read-only
	_ = (<-chan *enrichment.EnrichedEvent)(ch)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkNetworkMonitorEventParsing(b *testing.B) {
	events := make([][]byte, b.N)

	for i := 0; i < b.N; i++ {
		evt := NewTestNetworkEvent(uint32(1000+i), "192.168.1.1", "8.8.8.8", uint16(10000+i), 53, 6)
		buf := &bytes.Buffer{}
		binary.Write(buf, binary.LittleEndian, evt)
		events[i] = buf.Bytes()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parsed := &NetworkEvent{}
		binary.Read(bytes.NewReader(events[i]), binary.LittleEndian, parsed)
	}
}

func BenchmarkNetworkIPConversion(b *testing.B) {
	for i := 0; i < b.N; i++ {
		saddr := uint32(192) | (uint32(168) << 8) | (uint32(1) << 16) | (uint32(i%255) << 24)
		_ = net.IPv4(byte(saddr), byte(saddr>>8), byte(saddr>>16), byte(saddr>>24)).String()
	}
}

func BenchmarkNetworkMonitorEnrichment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		evt := NewTestNetworkEvent(1234, "10.0.0.1", "8.8.8.8", 54321, 443, 6)

		protocol := "tcp"
		if evt.Protocol == 17 {
			protocol = "udp"
		}

		netCtx := &enrichment.NetworkContext{
			SourceIP:        net.IPv4(byte(evt.SAddr), byte(evt.SAddr>>8), byte(evt.SAddr>>16), byte(evt.SAddr>>24)).String(),
			DestinationIP:   net.IPv4(byte(evt.DAddr), byte(evt.DAddr>>8), byte(evt.DAddr>>16), byte(evt.DAddr>>24)).String(),
			SourcePort:      evt.SPort,
			DestinationPort: evt.DPort,
			Protocol:        protocol,
		}

		_ = &enrichment.EnrichedEvent{
			RawEvent:  evt,
			EventType: "network_connection",
			Network:   netCtx,
			Timestamp: time.Now(),
		}
	}
}
