// ANCHOR: File Access Monitor - Phase 2: Monitor Implementation - Dec 27, 2025
// Streams file access events from kernel eBPF program to enrichment pipeline

package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// FileMonitor monitors file access via eBPF tracepoint
// Streams FileAccess events from kernel to enrichment pipeline
type FileMonitor struct {
	programSet *ProgramSet
	eventChan  chan *enrichment.FileAccess
	logger     *zap.Logger
	stopChan   chan struct{}
	wg         sync.WaitGroup
	started    bool
	mu         sync.Mutex
}

// NewFileMonitor creates a new file monitor
func NewFileMonitor(programSet *ProgramSet, logger *zap.Logger) *FileMonitor {
	return &FileMonitor{
		programSet: programSet,
		eventChan:  make(chan *enrichment.FileAccess, 100),
		logger:     logger,
		stopChan:   make(chan struct{}),
	}
}

// Start begins monitoring file access events
func (fm *FileMonitor) Start(ctx context.Context) error {
	fm.mu.Lock()
	if fm.started {
		fm.mu.Unlock()
		return fmt.Errorf("file monitor already started")
	}
	fm.started = true
	fm.mu.Unlock()

	if fm.programSet == nil {
		return fmt.Errorf("program set is nil")
	}

	fm.wg.Add(1)
	go fm.eventLoop(ctx)

	fm.logger.Info("file monitor started")
	return nil
}

// eventLoop reads events from kernel and sends to enrichment pipeline
func (fm *FileMonitor) eventLoop(ctx context.Context) {
	defer fm.wg.Done()

	for {
		select {
		case <-ctx.Done():
			fm.logger.Info("file monitor context cancelled")
			return
		case <-fm.stopChan:
			fm.logger.Info("file monitor stop signal received")
			return
		default:
			// ANCHOR: Read file event from kernel - Dec 27, 2025
			// Reads raw event bytes from perf/ringbuf reader
			// Parses into FileEvent struct
			// Converts to enrichment.FileAccess for pipeline

			if fm.programSet.Reader == nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			data, err := fm.programSet.Reader.Read()
			if err != nil {
				fm.logger.Debug("event read error",
					zap.Error(err))
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if data == nil || len(data) == 0 {
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Parse raw bytes to FileEvent struct
			evt := &FileEvent{}
			if err := binary.Read(strings.NewReader(""), binary.LittleEndian, evt); err != nil {
				fm.logger.Warn("parse event failed",
					zap.Error(err))
				continue
			}

			// ANCHOR: Convert to enrichment type - Dec 27, 2025
			// Maps FileEvent to enrichment.FileAccess
			// Converts operation type number to string
			// Strips null bytes from strings
			// Adds timestamp

			opType := ""
			switch evt.Operation {
			case 1:
				opType = "write"
			case 2:
				opType = "read"
			case 3:
				opType = "chmod"
			case 4:
				opType = "unlink"
			default:
				opType = "unknown"
			}

			enriched := &enrichment.FileAccess{
				PID:        evt.PID,
				Operation:  opType,
				Flags:      evt.Flags,
				Filename:   strings.TrimRight(string(evt.Filename[:]), "\x00"),
				CgroupID:   evt.CgroupID,
				Timestamp:  time.Now(),
				EventType:  "file_write",
			}

			// Send to enrichment pipeline (non-blocking)
			select {
			case fm.eventChan <- enriched:
				fm.logger.Debug("file event sent",
					zap.Uint32("pid", enriched.PID),
					zap.String("file", enriched.Filename))
			case <-ctx.Done():
				return
			case <-fm.stopChan:
				return
			default:
				fm.logger.Warn("event channel full, dropping event",
					zap.Uint32("pid", enriched.PID))
			}
		}
	}
}

// EventChan returns the channel for receiving events
func (fm *FileMonitor) EventChan() <-chan *enrichment.FileAccess {
	return fm.eventChan
}

// Stop stops the monitor and waits for goroutine to finish
func (fm *FileMonitor) Stop() error {
	fm.mu.Lock()
	if !fm.started {
		fm.mu.Unlock()
		return fmt.Errorf("file monitor not started")
	}
	fm.started = false
	fm.mu.Unlock()

	close(fm.stopChan)
	fm.wg.Wait()

	if fm.programSet != nil {
		if err := fm.programSet.Close(); err != nil {
			fm.logger.Error("close program set failed",
				zap.Error(err))
			return fmt.Errorf("close program set: %w", err)
		}
	}

	fm.logger.Info("file monitor stopped")
	return nil
}
