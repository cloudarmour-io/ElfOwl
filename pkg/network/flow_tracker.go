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
	"crypto/md5"
	"fmt"
	"sort"
	"sync"
	"time"
)

// FlowState represents simplified firewall-friendly TCP state machine (4 states)
type FlowState string

const (
	FlowStateNEW         FlowState = "new"          // SYN_SENT, SYN_RECV pending
	FlowStateESTABLISHED FlowState = "established"  // bidirectional data flow
	FlowStateCLOSING     FlowState = "closing"      // FIN_WAIT1, FIN_WAIT2, CLOSE_WAIT, LAST_ACK
	FlowStateCLOSED      FlowState = "closed"       // fully terminated
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
	Key               FlowKey
	State             FlowState
	CreatedAt         time.Time
	LastSeenAt        time.Time      // for TTL-based expiry
	BytesSent         uint64         // one direction
	BytesRecv         uint64         // reverse direction
	PacketsSent       uint64
	PacketsRecv       uint64
	CloseReason       string         // "fin", "reset", "timeout", "evicted"
	IsReversed        bool           // track if this is reverse direction of established flow
}

// FlowTracker correlates events into flows and manages flow state lifecycle
// ANCHOR: Flow tracker state machine - Feature: bidirectional flow correlation - Jul 18, 2026
// Maintains active flows with configurable TTL and memory limits.
// Emits closed flows to channel for webhook delivery.
type FlowTracker struct {
	flows            map[string]*FlowRecord  // key: flow key hash
	mu               sync.RWMutex
	activeTTL        time.Duration
	maxActiveFlows   int
	memoryLimitMB    int
	closedFlowsChan  chan *FlowRecord       // emit closed flows for webhook
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
		flow.State = newState

		// Track if this is reverse direction
		if (flow.Key.IP1 == srcIP && flow.Key.Port1 == srcPort) {
			// Forward direction
			flow.BytesSent += bytes
			flow.PacketsSent++
		} else {
			// Reverse direction
			flow.BytesRecv += bytes
			flow.PacketsRecv++
			isReversed = true
		}

		return &key, false, newState
	}

	// Create new flow
	isNewFlow = true
	flow := &FlowRecord{
		Key:        key,
		State:      FlowStateNEW,
		CreatedAt:  now,
		LastSeenAt: now,
		BytesSent:  bytes,
		PacketsSent: 1,
		IsReversed: isReversed,
	}

	ft.flows[keyStr] = flow

	// Check if we need to evict old flows due to memory pressure
	ft.evictIfNeeded()

	return &key, isNewFlow, FlowStateNEW
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
			// Channel full, drop (should not happen with buffered channel)
		}

		// Remove from active flows
		delete(ft.flows, keyStr)
	}
}

// ClosedFlows returns channel of closed flows for webhook emission
func (ft *FlowTracker) ClosedFlows() <-chan *FlowRecord {
	return ft.closedFlowsChan
}

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
			}

			delete(ft.flows, keyStr)
			expired++
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

	// Sort flows by LastSeenAt
	flows := make([]*FlowRecord, 0, len(ft.flows))
	for _, flow := range ft.flows {
		flows = append(flows, flow)
	}

	sort.Slice(flows, func(i, j int) bool {
		return flows[i].LastSeenAt.Before(flows[j].LastSeenAt)
	})

	// Evict oldest N
	for i := 0; i < count && i < len(flows); i++ {
		flow := flows[i]
		flow.State = FlowStateCLOSED
		flow.CloseReason = "evicted"

		// Emit to channel (non-blocking)
		select {
		case ft.closedFlowsChan <- flow:
		default:
		}

		delete(ft.flows, flow.Key.String())
	}
}

// Stats returns current flow table statistics (useful for metrics)
type FlowStats struct {
	ActiveFlows    int
	MemoryUsedMB   float64
	FlowsExpiredTTL int64
	FlowsEvictedMem int64
}

// Stats returns current flow table statistics
func (ft *FlowTracker) Stats() FlowStats {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	memUsed := float64((len(ft.flows) * 500)) / (1024.0 * 1024.0)

	return FlowStats{
		ActiveFlows:  len(ft.flows),
		MemoryUsedMB: memUsed,
	}
}

// createCanonicalFlowKey creates a canonical flow key with ordered IPs
// ANCHOR: Canonical flow key creation - Feature: bidirectional matching - Jul 18, 2026
// Ensures src→dst and dst→src events map to the same flow.
func createCanonicalFlowKey(srcIP, dstIP string, srcPort, dstPort uint16, protocol string, netnsID uint32) FlowKey {
	// Use string comparison for canonical ordering
	ips := []string{srcIP, dstIP}

	sort.Strings(ips)

	// Find which port corresponds to which IP
	key := FlowKey{
		IP1:      ips[0],
		IP2:      ips[1],
		Protocol: protocol,
		NetnsID:  netnsID,
	}

	if ips[0] == srcIP {
		key.Port1 = srcPort
		key.Port2 = dstPort
	} else {
		key.Port1 = dstPort
		key.Port2 = srcPort
	}

	return key
}
