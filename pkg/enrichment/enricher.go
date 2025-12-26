// ANCHOR: Event enrichment pipeline - Dec 26, 2025
// Converts goBPF events to enriched events with K8s and container context
// IMPLEMENTATION IN PROGRESS - Week 2 task

package enrichment

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	gobpfsecurity "github.com/udyansh/gobpf/security"

	"github.com/udyansh/elf-owl/pkg/agent"
	"github.com/udyansh/elf-owl/pkg/kubernetes"
)

// Enricher adds K8s context to raw goBPF events
type Enricher struct {
	K8sClient *kubernetes.Client
	Config    *agent.Config
	Logger    *zap.Logger
}

// NewEnricher creates a new event enricher
func NewEnricher(k8sClient *kubernetes.Client, config *agent.Config) (*Enricher, error) {
	logger, _ := zap.NewProduction()

	return &Enricher{
		K8sClient: k8sClient,
		Config:    config,
		Logger:    logger,
	}, nil
}

// EnrichProcessEvent enriches a goBPF process event
func (e *Enricher) EnrichProcessEvent(
	ctx context.Context,
	gobpfEvent *gobpfsecurity.ProcessEvent,
) (*EnrichedEvent, error) {
	if gobpfEvent == nil {
		return nil, fmt.Errorf("nil process event")
	}

	// TODO: Week 2 implementation
	// Step 1: Extract container ID from cgroup
	// Step 2: Query K8s API for pod metadata
	// Step 3: Query container runtime for labels
	// Step 4: Build enriched event

	enrichedEvent := &EnrichedEvent{
		RawEvent:  gobpfEvent,
		EventType: "process_execution",
		Timestamp: time.Now(),
		Kubernetes: &K8sContext{
			ClusterID: e.Config.Agent.ClusterID,
			NodeName:  e.Config.Agent.NodeName,
		},
		Container: &ContainerContext{},
	}

	return enrichedEvent, nil
}

// EnrichNetworkEvent enriches a goBPF network event
func (e *Enricher) EnrichNetworkEvent(
	ctx context.Context,
	gobpfEvent *gobpfsecurity.NetworkEvent,
) (*EnrichedEvent, error) {
	if gobpfEvent == nil {
		return nil, fmt.Errorf("nil network event")
	}

	// TODO: Week 2 implementation

	enrichedEvent := &EnrichedEvent{
		RawEvent:  gobpfEvent,
		EventType: "network_connection",
		Timestamp: time.Now(),
		Kubernetes: &K8sContext{
			ClusterID: e.Config.Agent.ClusterID,
			NodeName:  e.Config.Agent.NodeName,
		},
		Container: &ContainerContext{},
	}

	return enrichedEvent, nil
}

// EnrichDNSEvent enriches a goBPF DNS event
func (e *Enricher) EnrichDNSEvent(
	ctx context.Context,
	gobpfEvent *gobpfsecurity.DNSEvent,
) (*EnrichedEvent, error) {
	if gobpfEvent == nil {
		return nil, fmt.Errorf("nil DNS event")
	}

	// TODO: Week 2 implementation

	enrichedEvent := &EnrichedEvent{
		RawEvent:  gobpfEvent,
		EventType: "dns_query",
		Timestamp: time.Now(),
		Kubernetes: &K8sContext{
			ClusterID: e.Config.Agent.ClusterID,
			NodeName:  e.Config.Agent.NodeName,
		},
		Container: &ContainerContext{},
	}

	return enrichedEvent, nil
}

// EnrichFileEvent enriches a goBPF file event
func (e *Enricher) EnrichFileEvent(
	ctx context.Context,
	gobpfEvent *gobpfsecurity.FileEvent,
) (*EnrichedEvent, error) {
	if gobpfEvent == nil {
		return nil, fmt.Errorf("nil file event")
	}

	// TODO: Week 2 implementation

	enrichedEvent := &EnrichedEvent{
		RawEvent:  gobpfEvent,
		EventType: "file_access",
		Timestamp: time.Now(),
		Kubernetes: &K8sContext{
			ClusterID: e.Config.Agent.ClusterID,
			NodeName:  e.Config.Agent.NodeName,
		},
		Container: &ContainerContext{},
	}

	return enrichedEvent, nil
}

// EnrichCapabilityEvent enriches a goBPF capability event
func (e *Enricher) EnrichCapabilityEvent(
	ctx context.Context,
	gobpfEvent *gobpfsecurity.CapabilityEvent,
) (*EnrichedEvent, error) {
	if gobpfEvent == nil {
		return nil, fmt.Errorf("nil capability event")
	}

	// TODO: Week 2 implementation

	enrichedEvent := &EnrichedEvent{
		RawEvent:  gobpfEvent,
		EventType: "capability_usage",
		Timestamp: time.Now(),
		Kubernetes: &K8sContext{
			ClusterID: e.Config.Agent.ClusterID,
			NodeName:  e.Config.Agent.NodeName,
		},
		Container: &ContainerContext{},
	}

	return enrichedEvent, nil
}
