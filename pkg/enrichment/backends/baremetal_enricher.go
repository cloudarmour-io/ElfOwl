// ANCHOR: Bare-metal network enrichment - Feature: hostname, process, OS context for non-K8s networks - Jul 18, 2026
// Enriches network flows with host and process context from /proc filesystem.
// Used when agent runs on bare metal, VMs, or gateways without Kubernetes.
// Data sources:
// - /proc/net/tcp[6] for connection state (fallback if eBPF doesn't provide)
// - /proc/[pid]/* for process/user context (if PID available)
// - /etc/hostname or os.Hostname() for hostname
// - DNS reverse lookups for destination hostname (optional, configurable)
// - /proc/[pid]/attr/current for SELinux context (if available)

package backends

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/ebpf"
	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// BareMetalEnricher implements the Enricher interface for bare-metal/VM/gateway environments
// ANCHOR: Bare-metal enricher backend - Feature: environment-agnostic enrichment - Jul 18, 2026
// Provides hostname, process, user, and OS context without requiring Kubernetes API access.
// Optimized for low overhead on gateway/firewall deployments.
type BareMetalEnricher struct {
	logger      *zap.Logger
	config      BareMetalConfig
	hostname    string
	clusterID   string
	nodeName    string

	// Caches to reduce /proc and DNS lookups
	hostnameCacheMu sync.RWMutex
	hostnameCache   map[string]cacheEntry // IP → hostname with TTL

	processInfoCacheMu sync.RWMutex
	processInfoCache   map[uint32]cacheEntry // PID → process info with TTL
}

type cacheEntry struct {
	data      interface{}
	expiresAt time.Time
}

// NewBareMetalEnricher creates a new bare-metal enricher
// ANCHOR: Bare-metal enricher factory - Feature: pluggable enrichment - Jul 18, 2026
// Returns Enricher interface for compatibility with pluggable backend architecture.
func NewBareMetalEnricher(logger *zap.Logger, clusterID, nodeName string, config BareMetalConfig) (enrichment.Enricher, error) {
	if logger == nil {
		logger, _ = zap.NewProduction()
	}

	hostname, err := os.Hostname()
	if err != nil {
		logger.Warn("failed to get hostname", zap.Error(err))
		hostname = "unknown"
	}

	return &BareMetalEnricher{
		logger:            logger,
		config:            config,
		hostname:          hostname,
		clusterID:         clusterID,
		nodeName:          nodeName,
		hostnameCache:     make(map[string]cacheEntry),
		processInfoCache:  make(map[uint32]cacheEntry),
	}, nil
}

// Capabilities returns the enrichment capabilities of the bare-metal enricher
// ANCHOR: Bare-metal enricher capabilities - Feature: pluggable enrichment - Jul 18, 2026
// Bare-metal enricher supports network events only (process context comes from kernel).
func (be *BareMetalEnricher) Capabilities() enrichment.EnrichmentCapabilities {
	return enrichment.EnrichmentCapabilities{
		SupportsNetworkEnrichment:    true,
		SupportsDNSEnrichment:        false, // Phase 2+
		SupportsProcessEnrichment:    false, // Network events only in MVP
		SupportsFileEnrichment:       false,
		SupportsCapabilityEnrichment: false,
		SupportsTLSEnrichment:        false,
		BackendName:                  "bare-metal",
		RequiresK8sAPI:               false,
		RequiresHostFilesystem:       true,
	}
}

// EnrichNetworkEvent adds bare-metal context (hostname, process, user, SELinux)
// ANCHOR: Network event enrichment - Feature: bare-metal context - Jul 18, 2026
// Populates SourceEnrichment and DestEnrichment with BareMetalSourceContext.
// ANCHOR: Populate NetworkContext from raw event - Bug: flows never tracked - Aug 14, 2026
// Previously hardcoded SourceIP/DestinationIP to "0.0.0.0" and left SourcePort,
// DestinationPort, Protocol, Direction, ConnectionState, and NetworkNamespaceID at their zero
// values, discarding everything ebpf.NetworkMonitor already parsed from the raw eBPF event.
// Every network event collapsed to the same degenerate all-zero flow tuple, so
// FlowTracker never tracked real traffic and ConnectionState was always empty (flows
// permanently reported as "new"). Now type-asserts the raw *ebpf.NetworkEvent and maps it
// with the exact same helpers ebpf.NetworkMonitor uses, so both paths agree.
func (be *BareMetalEnricher) EnrichNetworkEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	// Check context timeout
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	enriched := &enrichment.EnrichedEvent{
		RawEvent:  rawEvent,
		EventType: "network_connection",
		Timestamp: time.Now(),
	}

	netEvt, ok := rawEvent.(*ebpf.NetworkEvent)
	if !ok {
		return nil, fmt.Errorf("bare-metal enricher: unexpected raw event type %T for network event", rawEvent)
	}

	sourceIP, destinationIP := ebpf.NetworkIPs(netEvt)
	enriched.Network = &enrichment.NetworkContext{
		SourceIP:           sourceIP,
		DestinationIP:      destinationIP,
		SourcePort:         netEvt.SPort,
		DestinationPort:    netEvt.DPort,
		Protocol:           ebpf.IPProtoName(netEvt.Protocol),
		Direction:          ebpf.NetworkDirection(netEvt.Direction),
		ConnectionState:    ebpf.TCPStateName(netEvt.State),
		NetworkNamespaceID: netEvt.NetNS,
	}

	// Enrich source context with hostname/process/user/SELinux info
	sourceCtx, err := be.enrichSourceContext(ctx, sourceIP, netEvt.PID)
	if err == nil && sourceCtx != nil {
		enriched.Network.SourceEnrichment = sourceCtx
	}

	return enriched, nil
}

// EnrichProcessEvent is not supported by bare-metal enricher in MVP
func (be *BareMetalEnricher) EnrichProcessEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	return nil, fmt.Errorf("bare-metal enricher does not support process event enrichment in MVP")
}

// EnrichDNSEvent is not supported by bare-metal enricher in MVP
func (be *BareMetalEnricher) EnrichDNSEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	return nil, fmt.Errorf("bare-metal enricher does not support DNS event enrichment in MVP")
}

// EnrichFileEvent is not supported by bare-metal enricher in MVP
func (be *BareMetalEnricher) EnrichFileEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	return nil, fmt.Errorf("bare-metal enricher does not support file event enrichment in MVP")
}

// EnrichCapabilityEvent is not supported by bare-metal enricher in MVP
func (be *BareMetalEnricher) EnrichCapabilityEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	return nil, fmt.Errorf("bare-metal enricher does not support capability event enrichment in MVP")
}

// EnrichTLSEvent is not supported by bare-metal enricher in MVP
func (be *BareMetalEnricher) EnrichTLSEvent(ctx context.Context, rawEvent interface{}) (*enrichment.EnrichedEvent, error) {
	return nil, fmt.Errorf("bare-metal enricher does not support TLS event enrichment in MVP")
}

// enrichSourceContext populates BareMetalSourceContext from IP + optional PID
// ANCHOR: Source context enrichment - Feature: hostname, process, OS context - Jul 18, 2026
// Attempts to resolve hostname via reverse DNS and process info via /proc.
func (be *BareMetalEnricher) enrichSourceContext(ctx context.Context, ip string, pid uint32) (*enrichment.BareMetalSourceContext, error) {
	sourceCtx := &enrichment.BareMetalSourceContext{
		Hostname: be.hostname, // Default to agent hostname
	}

	// Reverse DNS lookup if enabled
	if be.config.ReverseDNS {
		hostname, err := be.reverseDNS(ctx, ip)
		if err == nil && hostname != "" {
			sourceCtx.Hostname = hostname
		}
	}

	// Process info lookup if PID available and enabled
	if pid > 0 && be.config.ProcessLookup {
		procInfo, err := be.lookupProcessInfo(pid)
		if err == nil && procInfo != nil {
			sourceCtx.ProcessName = procInfo.ProcessName
			sourceCtx.ProcessPID = procInfo.ProcessPID
			sourceCtx.User = procInfo.User
			sourceCtx.UID = procInfo.UID
			sourceCtx.GID = procInfo.GID
		}
	}

	// SELinux context if enabled
	if be.config.SELinuxContext && pid > 0 {
		selinuxCtx, err := be.readSELinuxContext(pid)
		if err == nil && selinuxCtx != "" {
			sourceCtx.SELinuxContext = selinuxCtx
		}
	}

	return sourceCtx, nil
}

// reverseDNS looks up hostname from IP (cached, optional)
// ANCHOR: Reverse DNS lookup - Feature: hostname resolution - Jul 18, 2026
// Uses DNS reverse lookup to convert IP to hostname, with caching to reduce lookups.
func (be *BareMetalEnricher) reverseDNS(ctx context.Context, ip string) (string, error) {
	// Check cache first
	be.hostnameCacheMu.RLock()
	if entry, ok := be.hostnameCache[ip]; ok && time.Now().Before(entry.expiresAt) {
		defer be.hostnameCacheMu.RUnlock()
		if hostname, ok := entry.data.(string); ok {
			return hostname, nil
		}
	}
	be.hostnameCacheMu.RUnlock()

	// Perform reverse DNS lookup with timeout
	revCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(revCtx, ip)
	if err != nil || len(names) == 0 {
		return "", err
	}

	hostname := strings.TrimSuffix(names[0], ".")

	// Cache the result
	be.hostnameCacheMu.Lock()
	be.hostnameCache[ip] = cacheEntry{
		data:      hostname,
		expiresAt: time.Now().Add(be.config.HostnameCacheTTL),
	}
	be.hostnameCacheMu.Unlock()

	return hostname, nil
}

// ProcessInfo holds extracted process information
type ProcessInfo struct {
	ProcessName string
	ProcessPID  uint32
	User        string
	UID         uint32
	GID         uint32
}

// lookupProcessInfo reads /proc/[pid]/stat, /proc/[pid]/status for user/cmdline
// ANCHOR: Process info extraction - Feature: /proc parsing - Jul 18, 2026
// Extracts process name, owner UID/GID, and username from /proc filesystem.
func (be *BareMetalEnricher) lookupProcessInfo(pid uint32) (*ProcessInfo, error) {
	// Check cache first
	be.processInfoCacheMu.RLock()
	if entry, ok := be.processInfoCache[pid]; ok && time.Now().Before(entry.expiresAt) {
		defer be.processInfoCacheMu.RUnlock()
		if info, ok := entry.data.(*ProcessInfo); ok {
			return info, nil
		}
	}
	be.processInfoCacheMu.RUnlock()

	info := &ProcessInfo{ProcessPID: pid}

	// Read /proc/[pid]/status for UID/GID
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		return nil, err
	}

	// Parse UID and GID from status file
	for _, line := range strings.Split(string(statusData), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				uid, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					info.UID = uint32(uid)
				}
			}
		} else if strings.HasPrefix(line, "Gid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				gid, err := strconv.ParseUint(fields[1], 10, 32)
				if err == nil {
					info.GID = uint32(gid)
				}
			}
		} else if strings.HasPrefix(line, "Name:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				info.ProcessName = fields[1]
			}
		}
	}

	// Lookup username from UID
	if info.UID > 0 {
		u, err := user.LookupId(fmt.Sprintf("%d", info.UID))
		if err == nil {
			info.User = u.Username
		}
	}

	// Cache the result
	be.processInfoCacheMu.Lock()
	be.processInfoCache[pid] = cacheEntry{
		data:      info,
		expiresAt: time.Now().Add(be.config.ProcessCacheTTL),
	}
	be.processInfoCacheMu.Unlock()

	return info, nil
}

// readSELinuxContext reads SELinux context from /proc/[pid]/attr/current
// ANCHOR: SELinux context extraction - Feature: security policy - Jul 18, 2026
// Reads the current SELinux context if available on the system.
func (be *BareMetalEnricher) readSELinuxContext(pid uint32) (string, error) {
	selinuxPath := fmt.Sprintf("/proc/%d/attr/current", pid)
	data, err := os.ReadFile(selinuxPath)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}
