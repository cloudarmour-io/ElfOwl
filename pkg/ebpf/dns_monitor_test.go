// ANCHOR: Unit tests for DNSMonitor - Phase 3: Testing - Dec 27, 2025
// Tests DNS event monitoring, RFC 1035 type/code mapping, and enrichment

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
// DNSMonitor Creation & Initialization Tests
// ============================================================================

func TestNewDNSMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewDNSMonitor(nil, logger)

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
// DNSMonitor Lifecycle Tests
// ============================================================================

func TestDNSMonitorStart(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewDNSMonitor(programSet, logger)

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

func TestDNSMonitorStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewDNSMonitor(programSet, logger)

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
// DNSEvent Parsing Tests
// ============================================================================

func TestDNSEventParsing(t *testing.T) {
	testEvent := NewTestDNSEvent(1234, "example.com", 1, 0, 1)

	buf := &bytes.Buffer{}
	err := binary.Write(buf, binary.LittleEndian, testEvent)
	if err != nil {
		t.Fatalf("failed to serialize: %v", err)
	}

	parsed := &DNSEvent{}
	err = binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)
	if err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if parsed.PID != 1234 {
		t.Errorf("expected PID 1234, got %d", parsed.PID)
	}

	if parsed.QueryType != 1 {
		t.Errorf("expected QueryType 1 (A), got %d", parsed.QueryType)
	}

	if parsed.ResponseCode != 0 {
		t.Errorf("expected ResponseCode 0 (NOERROR), got %d", parsed.ResponseCode)
	}

	if parsed.QueryAllowed != 1 {
		t.Errorf("expected QueryAllowed 1, got %d", parsed.QueryAllowed)
	}
}

// ============================================================================
// DNS Query Type Mapping Tests (RFC 1035)
// ============================================================================

func TestDNSQueryTypeMapping(t *testing.T) {
	tests := []struct {
		qtype    uint16
		expected string
	}{
		{1, "A"},
		{2, "NS"},
		{5, "CNAME"},
		{6, "SOA"},
		{12, "PTR"},
		{15, "MX"},
		{16, "TXT"},
		{28, "AAAA"},
		{33, "SRV"},
		{42, "NAPTR"},
		{43, "DS"},
		{48, "DNSKEY"},
		{255, "ANY"},
		{999, "TYPE999"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := dnsQueryTypeName(tt.qtype)
			if name != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, name)
			}
		})
	}
}

// ============================================================================
// DNS Response Code Mapping Tests (RFC 1035)
// ============================================================================

func TestDNSResponseCodeMapping(t *testing.T) {
	tests := []struct {
		rcode    uint8
		expected string
	}{
		{0, "NOERROR"},
		{1, "FORMERR"},
		{2, "SERVFAIL"},
		{3, "NXDOMAIN"},
		{4, "NOTIMP"},
		{5, "REFUSED"},
		{6, "YXDOMAIN"},
		{7, "YXRRSET"},
		{8, "NXRRSET"},
		{9, "NOTAUTH"},
		{10, "NOTZONE"},
		{99, "RCODE99"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name := dnsResponseCodeName(tt.rcode)
			if name != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, name)
			}
		})
	}
}

// ============================================================================
// DNSContext Enrichment Tests
// ============================================================================

func TestDNSEnrichment(t *testing.T) {
	testEvent := NewTestDNSEvent(1234, "malicious.example.com", 28, 3, 0) // AAAA, NXDOMAIN, blocked

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	parsed := &DNSEvent{}
	binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, parsed)

	queryType := dnsQueryTypeName(parsed.QueryType)

	dnsCtx := &enrichment.DNSContext{
		QueryName:    "malicious.example.com",
		QueryType:    queryType,
		ResponseCode: int(parsed.ResponseCode),
		QueryAllowed: parsed.QueryAllowed == 1,
	}

	enriched := &enrichment.EnrichedEvent{
		RawEvent:  parsed,
		EventType: "dns_query",
		DNS:       dnsCtx,
		Timestamp: time.Now(),
	}

	// Verify
	AssertEnrichedEvent(t, enriched, "dns_query")
	AssertDNSContext(t, enriched.DNS, "malicious.example.com")

	if enriched.DNS.QueryType != "AAAA" {
		t.Errorf("expected query type 'AAAA', got %q", enriched.DNS.QueryType)
	}

	if enriched.DNS.QueryAllowed {
		t.Error("expected query allowed=false")
	}
}

// ============================================================================
// DNSMonitor Event Channel Tests
// ============================================================================

func TestDNSEventChannelFlow(t *testing.T) {
	logger := zaptest.NewLogger(t)

	testEvent := NewTestDNSEvent(1234, "google.com", 1, 0, 1)
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, testEvent)

	mockReader := NewMockReader(buf.Bytes())
	programSet := NewMockProgramSet(mockReader)
	monitor := NewDNSMonitor(programSet, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	monitor.Start(ctx)
	defer monitor.Stop()

	event := WaitForEvent(t, monitor.eventChan, 500*time.Millisecond)

	if event == nil {
		t.Fatal("expected event, got nil")
	}

	AssertEnrichedEvent(t, event, "dns_query")
}

// ============================================================================
// DNSMonitor Context Cancellation Tests
// ============================================================================

func TestDNSContextCancellation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	mockReader := NewMockReader()
	programSet := NewMockProgramSet(mockReader)
	monitor := NewDNSMonitor(programSet, logger)

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
// DNSMonitor Error Handling Tests
// ============================================================================

func TestDNSReaderError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	mockReader := NewMockReader()
	mockReader.readError = ErrSimulated
	programSet := NewMockProgramSet(mockReader)
	monitor := NewDNSMonitor(programSet, logger)

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
// DNSMonitor EventChan Return Type Test
// ============================================================================

func TestDNSEventChanReturnType(t *testing.T) {
	logger := zaptest.NewLogger(t)
	monitor := NewDNSMonitor(nil, logger)

	ch := monitor.EventChan()

	if ch == nil {
		t.Fatal("event channel is nil")
	}

	_ = (<-chan *enrichment.EnrichedEvent)(ch)
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkDNSMonitorEventParsing(b *testing.B) {
	events := make([][]byte, b.N)

	queryTypes := []uint16{1, 28, 15, 16, 2}
	responseCodes := []uint8{0, 3, 5}

	for i := 0; i < b.N; i++ {
		qtype := queryTypes[i%len(queryTypes)]
		rcode := responseCodes[i%len(responseCodes)]
		evt := NewTestDNSEvent(uint32(1000+i), "example.com", qtype, rcode, 1)
		buf := &bytes.Buffer{}
		binary.Write(buf, binary.LittleEndian, evt)
		events[i] = buf.Bytes()
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parsed := &DNSEvent{}
		binary.Read(bytes.NewReader(events[i]), binary.LittleEndian, parsed)
	}
}

func BenchmarkDNSQueryTypeLookup(b *testing.B) {
	queryTypes := []uint16{1, 28, 15, 16, 2, 5, 6, 12, 33, 42}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		qtype := queryTypes[i%len(queryTypes)]
		_ = dnsQueryTypeName(qtype)
	}
}

func BenchmarkDNSResponseCodeLookup(b *testing.B) {
	responseCodes := []uint8{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rcode := responseCodes[i%len(responseCodes)]
		_ = dnsResponseCodeName(rcode)
	}
}

func BenchmarkDNSMonitorEnrichment(b *testing.B) {
	for i := 0; i < b.N; i++ {
		evt := NewTestDNSEvent(1234, "example.com", 1, 0, 1)

		queryType := dnsQueryTypeName(evt.QueryType)

		dnsCtx := &enrichment.DNSContext{
			QueryName:    "example.com",
			QueryType:    queryType,
			ResponseCode: int(evt.ResponseCode),
			QueryAllowed: evt.QueryAllowed == 1,
		}

		_ = &enrichment.EnrichedEvent{
			RawEvent:  evt,
			EventType: "dns_query",
			DNS:       dnsCtx,
			Timestamp: time.Now(),
		}
	}
}
