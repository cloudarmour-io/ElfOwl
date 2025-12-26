// ANCHOR: Event enrichment data structures - Dec 26, 2025
// Defines enriched event types with Kubernetes and container context

package enrichment

import (
	"time"
)

// EnrichedEvent is an event with added K8s, container, and runtime context
type EnrichedEvent struct {
	// Original goBPF event
	RawEvent  interface{} `json:"raw_event"`
	EventType string      `json:"event_type"`

	// Kubernetes context
	Kubernetes *K8sContext `json:"kubernetes"`

	// Container context
	Container *ContainerContext `json:"container"`

	// Process/file/capability context (populated where applicable)
	Process    *ProcessContext    `json:"process"`
	File       *FileContext       `json:"file"`
	Capability *CapabilityContext `json:"capability"`

	// Derived fields
	Timestamp  time.Time `json:"timestamp"`
	Severity   string    `json:"severity"`
	CISControl string    `json:"cis_control"`
}

// K8sContext contains Kubernetes metadata
type K8sContext struct {
	ClusterID                   string            `json:"cluster_id"`
	NodeName                    string            `json:"node_name"`
	Namespace                   string            `json:"namespace"`
	PodName                     string            `json:"pod_name"`
	PodUID                      string            `json:"pod_uid"`
	ServiceAccount              string            `json:"service_account"`
	Image                       string            `json:"image"`
	ImageRegistry               string            `json:"image_registry"`
	ImageTag                    string            `json:"image_tag"`
	Labels                      map[string]string `json:"labels"`
	OwnerRef                    *OwnerReference   `json:"owner_ref"`
	AutomountServiceAccountToken bool             `json:"automount_service_account_token"`
	HasDefaultDenyNetworkPolicy  bool             `json:"has_default_deny_network_policy"`
}

// OwnerReference identifies the owner of a pod
type OwnerReference struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// ContainerContext contains container runtime metadata
type ContainerContext struct {
	ContainerID   string            `json:"container_id"`
	Runtime       string            `json:"runtime"`
	ContainerName string            `json:"container_name"`
	Labels        map[string]string `json:"labels"`
	Privileged    bool              `json:"privileged"`
	RunAsRoot     bool              `json:"run_as_root"`
}

// ProcessContext captures process metadata from goBPF events
type ProcessContext struct {
	PID         uint32 `json:"pid"`
	UID         uint32 `json:"uid"`
	GID         uint32 `json:"gid"`
	Command     string `json:"command"`
	Filename    string `json:"filename"`
	ContainerID string `json:"container_id"`
}

// FileContext captures file metadata from goBPF events
type FileContext struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
}

// CapabilityContext captures capability usage metadata
type CapabilityContext struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
	PID     uint32 `json:"pid"`
	UID     uint32 `json:"uid"`
}

// PodMetadata is the cached pod metadata
type PodMetadata struct {
	Name           string
	Namespace      string
	UID            string
	ServiceAccount string
	Image          string
	ImageRegistry  string
	ImageTag       string
	Labels         map[string]string
	OwnerRef       *OwnerReference
}

// NodeMetadata is the cached node metadata
type NodeMetadata struct {
	Name     string
	Labels   map[string]string
	Taints   []string
	Capacity map[string]string
}
