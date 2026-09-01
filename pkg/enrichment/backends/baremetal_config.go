// ANCHOR: Bare-metal enricher configuration - Feature: host-level context for non-K8s networks - Jul 18, 2026
// Configuration for bare-metal enrichment backend (gateway, bare-metal server, VM deployments).

package backends

import "time"

// BareMetalConfig defines configuration for the bare-metal enrichment backend
// ANCHOR: Bare-metal enricher config - Feature: configurable enrichment options - Jul 18, 2026
// Controls which enrichment sources are enabled (reverse DNS, process lookup, SELinux, etc.)
// and cache behavior for performance optimization.
type BareMetalConfig struct {
	// Enrichment sources
	ReverseDNS       bool   // Enable reverse DNS hostname lookups (IP → hostname)
	ProcessLookup    bool   // Enable /proc-based process info extraction
	SELinuxContext   bool   // Enable SELinux context reading from /proc
	GatewayServices  string // Path to gateway-services.yaml for port→service mapping

	// Cache settings
	HostnameCacheTTL time.Duration // How long to cache hostname lookups
	ProcessCacheTTL  time.Duration // How long to cache process info

	// Operational settings
	EnrichmentTimeout time.Duration // Maximum time to spend enriching a single event
}

// DefaultBareMetalConfig returns sensible defaults for bare-metal enrichment
func DefaultBareMetalConfig() BareMetalConfig {
	return BareMetalConfig{
		ReverseDNS:        true,
		ProcessLookup:     true,
		SELinuxContext:    true,
		GatewayServices:   "",
		HostnameCacheTTL:  5 * time.Minute,
		ProcessCacheTTL:   1 * time.Minute,
		EnrichmentTimeout: 500 * time.Millisecond,
	}
}
