// ANCHOR: TCP State Monitor - Feature: kernel TCP state tracking - Jul 22, 2026
// Monitors tcp_set_state kprobe events and updates flow states accordingly

package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/ringbuf"
	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/network"
)

// TCPStateMonitor monitors TCP state transitions from kernel
type TCPStateMonitor struct {
	Logger       *zap.Logger
	programSet   *ProgramSet
	reader       *ringbuf.Reader
	eventChannel chan *TCPStateEvent
	stopChan     chan struct{}
}

// TCPStateEvent represents a TCP state change event from kernel
// Note: This must match the struct definition in tcp_state.c
type TCPStateEvent struct {
	Timestamp uint64
	NewState  uint32
}

// NewTCPStateMonitor creates a new TCP state monitor
func NewTCPStateMonitor(logger *zap.Logger, programSet *ProgramSet) (*TCPStateMonitor, error) {
	if logger == nil {
		logger = zap.NewNop()
	}

	if programSet == nil {
		return nil, fmt.Errorf("invalid program set for tcp state monitor")
	}

	// Get the tcp_state_events map
	eventsMap := programSet.Maps["tcp_state_events"]
	if eventsMap == nil {
		logger.Warn("tcp_state_events map not found, tcp state tracking disabled")
		return nil, nil
	}

	// Create ringbuf reader for tcp_state_events
	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf reader for tcp state events: %w", err)
	}

	return &TCPStateMonitor{
		Logger:       logger,
		programSet:   programSet,
		reader:       reader,
		eventChannel: make(chan *TCPStateEvent, 100),
		stopChan:     make(chan struct{}),
	}, nil
}

// Start begins monitoring TCP state events
func (m *TCPStateMonitor) Start() error {
	if m.reader == nil {
		return fmt.Errorf("tcp state monitor not initialized")
	}

	go m.readEvents()
	m.Logger.Info("tcp state monitor started")
	return nil
}

// Stop stops the TCP state monitor
func (m *TCPStateMonitor) Stop() error {
	close(m.stopChan)

	if m.reader != nil {
		return m.reader.Close()
	}
	return nil
}

// readEvents reads and processes TCP state events from kernel
func (m *TCPStateMonitor) readEvents() {
	for {
		select {
		case <-m.stopChan:
			return
		default:
		}

		record, err := m.reader.Read()
		if err != nil {
			m.Logger.Error("failed to read tcp state event", zap.Error(err))
			continue
		}

		// Parse event from ringbuf
		var event TCPStateEvent
		reader := bytes.NewReader(record.RawSample)
		if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
			m.Logger.Error("failed to parse tcp state event", zap.Error(err))
			continue
		}

		// Filter out LISTEN state (server-side, not relevant for flow tracking)
		if event.NewState == 10 { // TCP_LISTEN
			continue
		}

		select {
		case m.eventChannel <- &event:
		case <-m.stopChan:
			return
		default:
			m.Logger.Warn("tcp state event channel full, dropping event",
				zap.Uint32("new_state", event.NewState),
			)
		}
	}
}

// Events returns the channel for receiving TCP state events
func (m *TCPStateMonitor) Events() <-chan *TCPStateEvent {
	return m.eventChannel
}

// StateTransitionName returns human-readable state name
func (m *TCPStateMonitor) StateTransitionName(newState uint32) string {
	return network.TCPStateName(newState)
}
