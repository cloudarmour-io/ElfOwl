# `pkg/evidence/buffer.go` — Event Batch Buffer

**Package:** `evidence`
**Path:** `pkg/evidence/buffer.go`
**Lines:** 98

---

## Overview

Thread-safe in-memory buffer that accumulates `EnrichedEvent` + `Violation` pairs until a size or age threshold is reached, at which point the agent flushes the batch for signing and pushing.

---

## Types

### `BufferedEvent`

```go
type BufferedEvent struct {
    EnrichedEvent *enrichment.EnrichedEvent
    Violations    []*rules.Violation
    Timestamp     time.Time
}
```

Pairs an enriched event with all rule violations it triggered and the time it was enqueued.

### `Buffer`

```go
type Buffer struct {
    events    []*BufferedEvent
    maxSize   int
    maxAge    time.Duration
    mu        sync.Mutex
    lastFlush time.Time
}
```

All methods lock `mu` before accessing `events`.

---

## Functions

### `NewBuffer(maxSize int, maxAge time.Duration) *Buffer`

Allocates a buffer pre-sized to `maxSize`. `lastFlush` is initialised to `time.Now()`.

### `Enqueue(event *enrichment.EnrichedEvent, violations []*rules.Violation)`

Appends a `BufferedEvent` with `Timestamp = time.Now()`. Does not enforce `maxSize` — the caller is expected to call `IsFull()` first and flush if needed.

### `Flush() []*BufferedEvent`

Returns and clears all buffered events. Resets `events` to a fresh slice pre-sized to `maxSize`. Updates `lastFlush`. Thread-safe.

### `IsFull() bool`

Returns `true` when `len(events) >= maxSize`.

### `IsStale() bool`

Returns `true` when the oldest event's `Timestamp` is older than `maxAge`. Returns `false` for an empty buffer.

### `Count() int`

Returns the current number of buffered events.

### `Clear()`

Discards all buffered events without returning them. Used on shutdown or error paths.

---

## Flush Triggers

The agent calls `IsFull()` and `IsStale()` after each event enqueue. Either condition triggers `Flush()` → sign → encrypt → push. This provides:

- **Bounded latency** via `maxAge` (default: configurable, typically 30–60 seconds)
- **Bounded memory** via `maxSize` (default: configurable, typically 100–500 events)

---

## Related Files

| File | Relationship |
|---|---|
| [signer.go](./signer.md) | Signs batch after flush |
| [cipher.go](./cipher.md) | Encrypts signed batch |
| [pkg/enrichment/types.go](../enrichment/types.md) | `EnrichedEvent` type stored in buffer |
| [pkg/rules/](../rules/) | `Violation` type stored alongside event |
