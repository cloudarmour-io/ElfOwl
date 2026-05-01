// ANCHOR: Network Connection Monitor - Phase 2: Monitor Implementation - Dec 27, 2025
// Streams network connection events from kernel eBPF program to enrichment pipeline

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// NetworkMonitor monitors network connections via eBPF tracepoint
// Streams NetworkConnection events from kernel to enrichment pipeline
type NetworkMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.EnrichedEvent
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex
	// ANCHOR: early protocol filter in eventLoop - Feature: network protocol filter - May 1, 2026
	// Filter is evaluated before the event enters eventChan so blocked protocols
	// never consume channel capacity. chanSize comes from config buffer_size.
	allowProtocols  []string
	ignoreProtocols []string
}

// NewNetworkMonitor creates a new network monitor.
// chanSize controls the eventChan buffer — pass config.Agent.EBPF.Network.BufferSize.
// allowProtocols / ignoreProtocols are the same values used by the enricher; applying
// them here prevents filtered events from ever entering the channel.
func NewNetworkMonitor(programSet *ProgramSet, logger *zap.Logger, chanSize int, allowProtocols, ignoreProtocols []string) *NetworkMonitor {
	return &NetworkMonitor{
		programSet:      programSet,
		eventChan:       make(chan *enrichment.EnrichedEvent, chanSize),
		logger:          logger,
		stopChan:        make(chan struct{}),
		allowProtocols:  allowProtocols,
		ignoreProtocols: ignoreProtocols,
	}
}

// protocolAllowed returns false when the protocol should be dropped before entering the channel.
func (nm *NetworkMonitor) protocolAllowed(protocol string) bool {
	p := strings.ToLower(protocol)
	if len(nm.allowProtocols) > 0 {
		matched := false
		for _, a := range nm.allowProtocols {
			if strings.ToLower(a) == p {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, ig := range nm.ignoreProtocols {
		if strings.ToLower(ig) == p {
			return false
		}
	}
	return true
}

// Start begins monitoring network connection events
func (nm *NetworkMonitor) Start(ctx context.Context) error {
	nm.mu.Lock()
	if nm.started {
		nm.mu.Unlock()
		return fmt.Errorf("network monitor already started")
	}
	nm.started = true
	nm.mu.Unlock()

	if nm.programSet == nil {
		return fmt.Errorf("program set is nil")
	}

	nm.wg.Add(1)
	go nm.eventLoop(ctx)

	nm.logger.Info("network monitor started")
	return nil
}

// eventLoop reads events from kernel and sends to enrichment pipeline
func (nm *NetworkMonitor) eventLoop(ctx context.Context) {
	defer nm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			nm.logger.Info("network monitor context cancelled")
			return
		case <-nm.stopChan:
			nm.logger.Info("network monitor stop signal received")
			return
		default:
			// ANCHOR: Read network event from kernel - Dec 27, 2025
			// Reads raw event bytes from perf/ringbuf reader
			// Parses into NetworkEvent struct using bytes.NewReader
			// Converts to enrichment.EnrichedEvent with NetworkContext

			if nm.programSet.Reader == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			data, err := nm.programSet.Reader.Read()
			if err != nil {
				nm.logger.Debug("event read error",
					zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if data == nil || len(data) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Parse raw bytes to NetworkEvent struct
			evt := &NetworkEvent{}
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, evt); err != nil {
				nm.logger.Warn("parse event failed",
					zap.Error(err))
				continue
			}

			// ANCHOR: Convert to enrichment type - Dec 27, 2025
			// Maps NetworkEvent to enrichment.EnrichedEvent with NetworkContext
			// Converts binary IP addresses to net.IP
			// Converts binary ports from network byte order
			// Adds timestamp

			// ANCHOR: early protocol filter in eventLoop - Feature: network protocol filter - May 1, 2026
			// Resolve protocol via shared IPProtoName table, then check filter before
			// allocating NetworkContext or touching the channel.
			protocol := IPProtoName(evt.Protocol)
			if !nm.protocolAllowed(protocol) {
				continue
			}

			sourceIP, destinationIP := networkIPs(evt)
			netCtx := &enrichment.NetworkContext{
				SourceIP:           sourceIP,
				DestinationIP:      destinationIP,
				SourcePort:         evt.SPort,
				DestinationPort:    evt.DPort,
				Protocol:           protocol,
				Direction:          networkDirection(evt.Direction),
				ConnectionState:    tcpStateName(evt.State),
				NetworkNamespaceID: evt.NetNS,
			}

			enriched := &enrichment.EnrichedEvent{
				RawEvent:  evt,
				EventType: "network_connection",
				Network:   netCtx,
				Timestamp: time.Now(),
			}

			// Send to enrichment pipeline (non-blocking)
			select {
			case nm.eventChan <- enriched:
				nm.logger.Debug("network event sent",
					zap.Uint32("pid", evt.PID),
					zap.String("src", netCtx.SourceIP),
					zap.Uint16("src_port", netCtx.SourcePort),
					zap.String("dest", netCtx.DestinationIP),
					zap.Uint16("dest_port", netCtx.DestinationPort),
					zap.String("protocol", netCtx.Protocol))
			case <-ctx.Done():
				return
			case <-nm.stopChan:
				return
			default:
				nm.logger.Warn("event channel full, dropping event",
					zap.Uint32("pid", evt.PID))
			}
		}
	}
}

// ANCHOR: Network direction/state mapping - Feature: advanced telemetry - Mar 25, 2026
// Converts kernel numeric enums to human-readable strings for enrichment.
func networkDirection(direction uint8) string {
	switch direction {
	case 1:
		return "outbound"
	case 2:
		return "inbound"
	default:
		return "unknown"
	}
}

func tcpStateName(state uint8) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	case 12:
		return "NEW_SYN_RECV"
	default:
		return "UNKNOWN"
	}
}

func networkIPs(evt *NetworkEvent) (string, string) {
	if evt.Family == AF_INET6 {
		return net.IP(evt.SAddrV6[:]).String(), net.IP(evt.DAddrV6[:]).String()
	}
	source := net.IPv4(byte(evt.SAddr), byte(evt.SAddr>>8), byte(evt.SAddr>>16), byte(evt.SAddr>>24)).String()
	destination := net.IPv4(byte(evt.DAddr), byte(evt.DAddr>>8), byte(evt.DAddr>>16), byte(evt.DAddr>>24)).String()
	return source, destination
}

// EventChan returns the channel for receiving events
func (nm *NetworkMonitor) EventChan() <-chan *enrichment.EnrichedEvent {
	return nm.eventChan
}

// Stop stops the monitor and waits for goroutine to finish
func (nm *NetworkMonitor) Stop() error {
	nm.mu.Lock()
	if !nm.started {
		nm.mu.Unlock()
		return fmt.Errorf("network monitor not started")
	}
	nm.started = false
	nm.mu.Unlock()

	close(nm.stopChan)
	nm.wg.Wait()

	if nm.programSet != nil {
		if err := nm.programSet.Close(); err != nil {
			nm.logger.Error("close program set failed",
				zap.Error(err))
			return fmt.Errorf("close program set: %w", err)
		}
	}

	nm.logger.Info("network monitor stopped")
	return nil
}
