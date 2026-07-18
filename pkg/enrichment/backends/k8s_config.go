// ANCHOR: K8s enricher configuration - Feature: optional Kubernetes context - Jul 18, 2026
// Configuration for Kubernetes enrichment backend (K8s cluster deployments).

package backends

import "time"

// K8sConfig defines configuration for the Kubernetes enrichment backend
// ANCHOR: K8s enricher config - Feature: configurable enrichment options - Jul 18, 2026
// Controls K8s API caching, metadata extraction, and enrichment behavior.
type K8sConfig struct {
	// File/network filter configuration (from agent config)
	WatchPaths      []string
	IgnorePaths     []string
	AllowProtocols  []string
	IgnoreProtocols []string

	// Cache settings
	MetadataCacheTTL     time.Duration
	CgroupRefreshInterval time.Duration

	// Operational settings
	EnrichmentTimeout time.Duration
}

// DefaultK8sConfig returns sensible defaults for K8s enrichment
func DefaultK8sConfig() K8sConfig {
	return K8sConfig{
		MetadataCacheTTL:     5 * time.Minute,
		CgroupRefreshInterval: 30 * time.Second,
		EnrichmentTimeout:     2 * time.Second,
	}
}
