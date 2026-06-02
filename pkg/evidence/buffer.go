// ANCHOR: Event buffering and batching - Dec 26, 2025
// Buffers enriched events for batch push to Owl SaaS

package evidence

import (
	"sync"
	"time"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/rules"
)

// BufferedEvent holds an enriched event with its violations.
type BufferedEvent struct {
	EnrichedEvent *enrichment.EnrichedEvent
	Violations    []*rules.Violation
	Timestamp     time.Time
	queueKey      string `json:"-"`
}

// BufferOption customizes Buffer construction.
type BufferOption func(*Buffer)

// WithDurableStore enables a file-backed queue rooted at dirPath.
func WithDurableStore(dirPath string) BufferOption {
	return func(buffer *Buffer) {
		if buffer == nil {
			return
		}
		store, err := newDurableStore(dirPath)
		if err != nil {
			buffer.initErr = err
			return
		}
		buffer.store = store
	}
}

// Buffer batches events for efficient pushing.
type Buffer struct {
	events    []*BufferedEvent
	inFlight  map[string]*BufferedEvent
	maxSize   int
	maxAge    time.Duration
	store     *durableStore
	initErr   error
	mu        sync.Mutex
	lastFlush time.Time
}

// NewBuffer creates a new event buffer.
func NewBuffer(maxSize int, maxAge time.Duration, options ...BufferOption) *Buffer {
	buffer := &Buffer{
		events:    make([]*BufferedEvent, 0, maxSize),
		inFlight:  make(map[string]*BufferedEvent),
		maxSize:   maxSize,
		maxAge:    maxAge,
		lastFlush: time.Now(),
	}

	for _, option := range options {
		if option != nil {
			option(buffer)
		}
	}

	if buffer.store != nil {
		buffer.events = append(buffer.events, buffer.store.Load()...)
		if len(buffer.events) > 0 {
			buffer.lastFlush = buffer.events[0].Timestamp
		}
	}

	return buffer
}

// InitError returns a durable queue initialization error, if any.
func (b *Buffer) InitError() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.initErr
}

// Enqueue adds an event to the buffer.
func (b *Buffer) Enqueue(event *enrichment.EnrichedEvent, violations []*rules.Violation) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	bufferedEvent := &BufferedEvent{
		EnrichedEvent: event,
		Violations:    violations,
		Timestamp:     time.Now(),
	}
	if b.store != nil {
		if err := b.store.Enqueue(bufferedEvent); err != nil {
			return err
		}
	}

	b.events = append(b.events, bufferedEvent)
	return nil
}

// Flush returns the next batch of buffered events and moves them into an in-flight set.
func (b *Buffer) Flush() []*BufferedEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	flushCount := len(b.events)
	if flushCount > b.maxSize {
		flushCount = b.maxSize
	}
	events := append([]*BufferedEvent(nil), b.events[:flushCount]...)
	for _, event := range events {
		if event != nil && event.queueKey != "" {
			b.inFlight[event.queueKey] = event
		}
	}
	b.events = append([]*BufferedEvent(nil), b.events[flushCount:]...)
	b.lastFlush = time.Now()

	return events
}

// Ack permanently removes flushed events from the durable queue.
func (b *Buffer) Ack(events []*BufferedEvent) error {
	if len(events) == 0 {
		return nil
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.store != nil {
		if err := b.store.Ack(events); err != nil {
			return err
		}
	}
	for _, event := range events {
		if event != nil && event.queueKey != "" {
			delete(b.inFlight, event.queueKey)
		}
	}
	return nil
}

// RequeueFront prepends previously flushed events back onto the buffer.
func (b *Buffer) RequeueFront(events []*BufferedEvent) {
	if len(events) == 0 {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	requeued := make([]*BufferedEvent, 0, len(events)+len(b.events))
	requeued = append(requeued, events...)
	requeued = append(requeued, b.events...)
	b.events = requeued
	for _, event := range events {
		if event != nil && event.queueKey != "" {
			delete(b.inFlight, event.queueKey)
		}
	}
}

// IsFull returns true if queued events have reached the configured batch size.
func (b *Buffer) IsFull() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.events) >= b.maxSize
}

// IsStale returns true if the oldest queued event exceeds max age.
func (b *Buffer) IsStale() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) == 0 {
		return false
	}

	return time.Since(b.events[0].Timestamp) > b.maxAge
}

// Count returns the current number of unacked events, including in-flight batches.
func (b *Buffer) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.events) + len(b.inFlight)
}

// OldestAge returns the age of the oldest unacked event.
func (b *Buffer) OldestAge() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	oldest := oldestEventTimestamp(b.events, b.inFlight)
	if oldest.IsZero() {
		return 0
	}
	return time.Since(oldest)
}

// DurablePath returns the backing queue path when durability is enabled.
func (b *Buffer) DurablePath() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.store == nil {
		return ""
	}
	return b.store.dirPath
}

// Clear clears the buffer without returning events.
func (b *Buffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = make([]*BufferedEvent, 0, b.maxSize)
	b.inFlight = make(map[string]*BufferedEvent)
	if b.store != nil {
		_ = b.store.Clear()
	}
}

func oldestEventTimestamp(queued []*BufferedEvent, inFlight map[string]*BufferedEvent) time.Time {
	var oldest time.Time
	for _, event := range queued {
		oldest = minEventTimestamp(oldest, event)
	}
	for _, event := range inFlight {
		oldest = minEventTimestamp(oldest, event)
	}
	return oldest
}

func minEventTimestamp(current time.Time, event *BufferedEvent) time.Time {
	if event == nil || event.Timestamp.IsZero() {
		return current
	}
	if current.IsZero() || event.Timestamp.Before(current) {
		return event.Timestamp
	}
	return current
}
