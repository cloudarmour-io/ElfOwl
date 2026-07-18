// ANCHOR: Kubernetes enricher backend - Feature: optional K8s context - Jul 18, 2026
// Wraps the K8sEnricher implementation from the parent enrichment package.
// Makes K8s enrichment available as a pluggable backend alongside bare-metal.

package backends

import (
	"fmt"

	"github.com/udyansh/elf-owl/pkg/enrichment"
	"github.com/udyansh/elf-owl/pkg/kubernetes"
)

// NewK8sEnricher creates a new Kubernetes enricher backend
// ANCHOR: K8s enricher factory - Feature: pluggable enrichment - Jul 18, 2026
// Wrapper that calls the enrichment package's K8sEnricher constructor.
// Returns Enricher interface for compatibility with pluggable backend architecture.
func NewK8sEnricherBackend(k8sClient *kubernetes.Client, clusterID, nodeName string,
	watchPaths, ignorePaths []string,
	allowProtocols, ignoreProtocols []string,
) (enrichment.Enricher, error) {
	if k8sClient == nil {
		return nil, fmt.Errorf("kubernetes client is required for K8s enricher")
	}

	// Call the enrichment package's NewK8sEnricher function
	return enrichment.NewK8sEnricher(k8sClient, clusterID, nodeName,
		watchPaths, ignorePaths,
		allowProtocols, ignoreProtocols)
}

// Note: Full K8sEnricher implementation is in pkg/enrichment/enricher.go
// This backend wrapper provides a consistent interface with other backends like BareMetalEnricher.
