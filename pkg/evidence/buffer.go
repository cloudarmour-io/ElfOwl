// ANCHOR: Event buffering and batching - Dec 26, 2025
// Buffers enriched events for batch push to Owl SaaS

package evidence

import (
	"sync"
	"time"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/rules"
)

// BufferedEvent holds an enriched event with its violations
type BufferedEvent struct {
	EnrichedEvent *enrichment.EnrichedEvent
	Violations    []*rules.Violation
	Timestamp     time.Time
}

// Buffer batches events for efficient pushing
type Buffer struct {
	events     []*BufferedEvent
	maxSize    int
	maxAge     time.Duration
	mu         sync.Mutex
	lastFlush  time.Time
}

// NewBuffer creates a new event buffer
func NewBuffer(maxSize int, maxAge time.Duration) *Buffer {
	return &Buffer{
		events:    make([]*BufferedEvent, 0, maxSize),
		maxSize:   maxSize,
		maxAge:    maxAge,
		lastFlush: time.Now(),
	}
}

// Enqueue adds an event to the buffer
func (b *Buffer) Enqueue(event *enrichment.EnrichedEvent, violations []*rules.Violation) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = append(b.events, &BufferedEvent{
		EnrichedEvent: event,
		Violations:    violations,
		Timestamp:     time.Now(),
	})
}

// Flush returns all buffered events and clears the buffer
func (b *Buffer) Flush() []*BufferedEvent {
	b.mu.Lock()
	defer b.mu.Unlock()

	events := b.events
	b.events = make([]*BufferedEvent, 0, b.maxSize)
	b.lastFlush = time.Now()

	return events
}

// IsFull returns true if buffer has reached max size
func (b *Buffer) IsFull() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.events) >= b.maxSize
}

// IsStale returns true if oldest event exceeds max age
func (b *Buffer) IsStale() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.events) == 0 {
		return false
	}

	return time.Since(b.events[0].Timestamp) > b.maxAge
}

// Count returns current number of buffered events
func (b *Buffer) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return len(b.events)
}

// Clear clears the buffer without returning events
func (b *Buffer) Clear() {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.events = make([]*BufferedEvent, 0, b.maxSize)
}
