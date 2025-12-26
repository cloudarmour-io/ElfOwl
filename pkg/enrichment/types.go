// ANCHOR: Event enrichment data structures - Dec 26, 2025
// Defines enriched event types with Kubernetes and container context

package enrichment

import (
	"time"
)

// EnrichedEvent is an event with added K8s and container context
type EnrichedEvent struct {
	// Original goBPF event
	RawEvent  interface{} `json:"raw_event"`
	EventType string      `json:"event_type"`

	// Kubernetes context
	Kubernetes *K8sContext `json:"kubernetes"`

	// Container context
	Container *ContainerContext `json:"container"`

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
