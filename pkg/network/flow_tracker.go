// ANCHOR: Bidirectional network flow tracking - Feature: conntrack-style correlation for firewall/gateway - Jul 18, 2026
// Correlates unidirectional kernel events (tcp_connect, inet_sock_set_state, UDP sendto) into
// bidirectional flows using canonical tuple matching. Tracks state progression (NEW → ESTABLISHED → CLOSING → CLOSED)
// with configurable TTL-based expiry and memory limits. Enables firewalls/gateways to:
// - Track session state transitions and lifetime
// - Count bytes/packets per bidirectional flow
// - Detect port scans, DDoS floods, data exfiltration
// - Emit flow_summary webhook events when flows close

package network

import (
	"container/heap"
	"crypto/md5"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FlowState represents simplified firewall-friendly TCP state machine (4 states)
type FlowState string

const (
	FlowStateNEW         FlowState = "new"         // SYN_SENT, SYN_RECV pending
	FlowStateESTABLISHED FlowState = "established" // bidirectional data flow
	FlowStateCLOSING     FlowState = "closing"     // FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT, LAST_ACK
	FlowStateCLOSED      FlowState = "closed"      // fully terminated
)

// FlowKey uniquely identifies a bidirectional flow (order-independent)
// ANCHOR: Bidirectional flow key - Feature: conntrack-style flow identification - Jul 18, 2026
// Canonical ordering ensures src→dst and dst→src events map to the same flow.
// Uses string comparison for canonical ordering: min(src, dst) as IP1, max as IP2.
type FlowKey struct {
	IP1      string // canonical: min(src, dst) by string comparison
	Port1    uint16 // port associated with IP1
	IP2      string // canonical: max(src, dst)
	Port2    uint16 // port associated with IP2
	Protocol string // tcp, udp, icmp, ...
	NetnsID  uint32 // network namespace for multi-tenancy
}

// String returns a hash representation of the flow key
func (fk *FlowKey) String() string {
	// Create canonical string for hashing
	h := md5.New()
	h.Write([]byte(fmt.Sprintf("%s:%d:%s:%d:%s:%d", fk.IP1, fk.Port1, fk.IP2, fk.Port2, fk.Protocol, fk.NetnsID)))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// FlowRecord tracks bidirectional flow state and metrics
type FlowRecord struct {
	Key         FlowKey
	State       FlowState
	CreatedAt   time.Time
	LastSeenAt  time.Time // for TTL-based expiry
	BytesSent   uint64    // one direction
	BytesRecv   uint64    // reverse direction
	PacketsSent uint64
	PacketsRecv uint64
	CloseReason string // "fin", "reset", "timeout", "evicted"
	IsReversed  bool   // track if this is reverse direction of established flow
	heapIndex   int
}

// FlowTracker correlates events into flows and manages flow state lifecycle
// ANCHOR: Flow tracker state machine - Feature: bidirectional flow correlation - Jul 18, 2026
// Maintains active flows with configurable TTL and memory limits.
// Emits closed flows to channel for webhook delivery.
type FlowTracker struct {
	flows              map[string]*FlowRecord // key: flow key hash
	mu                 sync.RWMutex
	activeTTL          time.Duration
	maxActiveFlows     int
	memoryLimitMB      int
	closedFlowsChan    chan *FlowRecord // emit closed flows for webhook
	closedFlowsDropped atomic.Uint64
	flowsExpiredTTL    atomic.Int64
	flowsEvicted       atomic.Int64
	oldest             flowHeap
}

// NewFlowTracker creates tracker with configurable TTL and memory limits
func NewFlowTracker(activeTTL time.Duration, maxFlows int, memLimitMB int) *FlowTracker {
	if activeTTL == 0 {
		activeTTL = 30 * time.Minute
	}
	if maxFlows == 0 {
		maxFlows = 500000
	}
	if memLimitMB == 0 {
		memLimitMB = 256
	}

	return &FlowTracker{
		flows:           make(map[string]*FlowRecord),
		activeTTL:       activeTTL,
		maxActiveFlows:  maxFlows,
		memoryLimitMB:   memLimitMB,
		closedFlowsChan: make(chan *FlowRecord, 1000), // buffered channel
	}
}

// AddOrUpdateFlow correlates a network event into a flow
// Returns (flowKey, isNewFlow, flowState)
// ANCHOR: Flow correlation logic - Feature: bidirectional tuple matching - Jul 18, 2026
// Creates new flow or updates existing one based on canonical key matching.
// Simplified 4-state state machine: NEW → ESTABLISHED → CLOSING → CLOSED
func (ft *FlowTracker) AddOrUpdateFlow(srcIP, dstIP string, srcPort, dstPort uint16,
	protocol string, netnsID uint32, bytes uint64, newState FlowState) (*FlowKey, bool, FlowState) {

	ft.mu.Lock()
	defer ft.mu.Unlock()

	// Create canonical flow key (order-independent)
	key := createCanonicalFlowKey(srcIP, dstIP, srcPort, dstPort, protocol, netnsID)
	keyStr := key.String()

	// Check if flow exists
	now := time.Now()
	isNewFlow := false
	isReversed := false

	if flow, exists := ft.flows[keyStr]; exists {
		// Update existing flow
		flow.LastSeenAt = now
		heap.Fix(&ft.oldest, flow.heapIndex)
		flow.State = nextFlowState(flow.State, newState)

		// Track if this is reverse direction
		if flow.Key.IP1 == srcIP && flow.Key.Port1 == srcPort {
			// Forward direction
			flow.BytesSent += bytes
			flow.PacketsSent++
		} else {
			// Reverse direction
			flow.BytesRecv += bytes
			flow.PacketsRecv++
			isReversed = true
		}

		return &key, false, flow.State
	}

	// Create new flow
	isNewFlow = true
	flow := &FlowRecord{
		Key:         key,
		State:       newState,
		CreatedAt:   now,
		LastSeenAt:  now,
		BytesSent:   bytes,
		PacketsSent: 1,
		IsReversed:  isReversed,
		heapIndex:   -1,
	}

	ft.flows[keyStr] = flow
	heap.Push(&ft.oldest, flow)

	// Check if we need to evict old flows due to memory pressure
	ft.evictIfNeeded()

	return &key, isNewFlow, newState
}

// IsReversed reports the direction of the most recent event for a flow.
func (ft *FlowTracker) IsReversed(key *FlowKey) bool {
	if key == nil {
		return false
	}
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	if flow, ok := ft.flows[key.String()]; ok {
		return flow.IsReversed
	}
	return false
}

// GetFlowState returns current state of a flow or nil if not found
func (ft *FlowTracker) GetFlowState(key *FlowKey) FlowState {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	if flow, exists := ft.flows[key.String()]; exists {
		return flow.State
	}
	return ""
}

// CloseFlow marks flow as CLOSED and emits to closedFlowsChan
func (ft *FlowTracker) CloseFlow(key *FlowKey, reason string) {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	keyStr := key.String()
	if flow, exists := ft.flows[keyStr]; exists {
		flow.State = FlowStateCLOSED
		flow.CloseReason = reason
		flow.LastSeenAt = time.Now()

		// Emit to channel (non-blocking)
		select {
		case ft.closedFlowsChan <- flow:
		default:
			ft.closedFlowsDropped.Add(1)
		}

		// Remove from active flows
		delete(ft.flows, keyStr)
		heap.Remove(&ft.oldest, flow.heapIndex)
	}
}

// ClosedFlows returns channel of closed flows for webhook emission
func (ft *FlowTracker) ClosedFlows() <-chan *FlowRecord {
	return ft.closedFlowsChan
}

func (ft *FlowTracker) ActiveTTL() time.Duration { return ft.activeTTL }
func (ft *FlowTracker) MaxActiveFlows() int      { return ft.maxActiveFlows }
func (ft *FlowTracker) MemoryLimitMB() int       { return ft.memoryLimitMB }

// ExpireOldFlows removes flows idle > activeTTL; called periodically (every 10s)
// ANCHOR: Flow TTL expiry - Feature: configurable flow timeout - Jul 18, 2026
// Removes idle flows to prevent unbounded memory growth.
func (ft *FlowTracker) ExpireOldFlows() int {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	now := time.Now()
	expired := 0

	for keyStr, flow := range ft.flows {
		if now.Sub(flow.LastSeenAt) > ft.activeTTL {
			flow.State = FlowStateCLOSED
			flow.CloseReason = "timeout"

			// Emit to channel (non-blocking)
			select {
			case ft.closedFlowsChan <- flow:
			default:
				ft.closedFlowsDropped.Add(1)
			}

			delete(ft.flows, keyStr)
			heap.Remove(&ft.oldest, flow.heapIndex)
			expired++
			ft.flowsExpiredTTL.Add(1)
		}
	}

	return expired
}

// evictIfNeeded removes oldest flows if count > maxActiveFlows or memory > limit
// ANCHOR: Flow eviction - Feature: memory-bounded tracking - Jul 18, 2026
// Uses LRU (least recently used) eviction when limits exceeded.
func (ft *FlowTracker) evictIfNeeded() {
	// Check if over flow count limit
	if len(ft.flows) > ft.maxActiveFlows {
		ft.evictOldest(len(ft.flows) - ft.maxActiveFlows)
	}

	// Check memory usage (rough estimate: ~500 bytes per flow)
	estimatedMemMB := (len(ft.flows) * 500) / (1024 * 1024)
	if estimatedMemMB > ft.memoryLimitMB {
		toEvict := (estimatedMemMB - ft.memoryLimitMB) / 50 // rough estimate
		if toEvict < 1 {
			toEvict = 1
		}
		ft.evictOldest(toEvict)
	}
}

// evictOldest removes N oldest flows by LastSeenAt time
func (ft *FlowTracker) evictOldest(count int) {
	if count <= 0 || len(ft.flows) == 0 {
		return
	}

	// Evict oldest N
	for i := 0; i < count && ft.oldest.Len() > 0; i++ {
		flow := heap.Pop(&ft.oldest).(*FlowRecord)
		flow.State = FlowStateCLOSED
		flow.CloseReason = "evicted"

		// Emit to channel (non-blocking)
		select {
		case ft.closedFlowsChan <- flow:
		default:
			ft.closedFlowsDropped.Add(1)
		}

		delete(ft.flows, flow.Key.String())
		ft.flowsEvicted.Add(1)
	}
}

type flowHeap []*FlowRecord

func (h flowHeap) Len() int           { return len(h) }
func (h flowHeap) Less(i, j int) bool { return h[i].LastSeenAt.Before(h[j].LastSeenAt) }
func (h flowHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].heapIndex, h[j].heapIndex = i, j
}
func (h *flowHeap) Push(value interface{}) {
	flow := value.(*FlowRecord)
	flow.heapIndex = len(*h)
	*h = append(*h, flow)
}
func (h *flowHeap) Pop() interface{} {
	old := *h
	n := len(old)
	flow := old[n-1]
	flow.heapIndex = -1
	*h = old[:n-1]
	return flow
}

// Stats returns current flow table statistics (useful for metrics)
type FlowStats struct {
	ActiveFlows        int
	MemoryUsedMB       float64
	FlowsExpiredTTL    int64
	FlowsEvictedMem    int64
	ClosedFlowsDropped uint64
}

// Stats returns current flow table statistics
func (ft *FlowTracker) Stats() FlowStats {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	memUsed := float64((len(ft.flows) * 500)) / (1024.0 * 1024.0)

	return FlowStats{
		ActiveFlows:        len(ft.flows),
		MemoryUsedMB:       memUsed,
		ClosedFlowsDropped: ft.closedFlowsDropped.Load(),
		FlowsExpiredTTL:    ft.flowsExpiredTTL.Load(),
		FlowsEvictedMem:    ft.flowsEvicted.Load(),
	}
}

// createCanonicalFlowKey creates a canonical flow key with ordered IPs
// ANCHOR: Canonical flow key creation - Feature: bidirectional matching - Jul 18, 2026
// Ensures src→dst and dst→src events map to the same flow.
func createCanonicalFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, netnsID uint32) FlowKey {
	srcIP = normalizeIP(srcIP)
	dstIP = normalizeIP(dstIP)
	// Break equal-IP ties by port so loopback flows also canonicalize.
	if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}
	return FlowKey{
		IP1:      srcIP,
		Port1:    srcPort,
		IP2:      dstIP,
		Port2:    dstPort,
		Protocol: protocol,
		NetnsID:  netnsID,
	}
}

func normalizeIP(value string) string {
	if parsed := net.ParseIP(strings.TrimSpace(value)); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return strings.TrimSpace(value)
}

func nextFlowState(current, incoming FlowState) FlowState {
	if incoming == "" || current == FlowStateCLOSED {
		return current
	}
	if incoming == FlowStateCLOSED || current == FlowStateNEW {
		return incoming
	}
	if current == FlowStateESTABLISHED && incoming == FlowStateNEW {
		return current
	}
	if current == FlowStateCLOSING && incoming != FlowStateCLOSED {
		return current
	}
	return incoming
}
