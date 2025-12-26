// ANCHOR: Kubernetes API client - Dec 26, 2025
// Provides read-only K8s API access for metadata enrichment
// IMPLEMENTATION IN PROGRESS - Week 4 task

package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client provides read-only access to Kubernetes API
type Client struct {
	clientset *kubernetes.Clientset
	config    *rest.Config
	cache     *MetadataCache
}

// NewClient creates a new Kubernetes API client
func NewClient(inCluster bool) (*Client, error) {
	var config *rest.Config
	var err error

	if inCluster {
		// Use in-cluster configuration (running in pod)
		config, err = rest.InClusterConfig()
	} else {
		// Use kubeconfig from environment or home directory
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = filepath.Join(os.Getenv("HOME"), ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to load Kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes clientset: %w", err)
	}

	return &Client{
		clientset: clientset,
		config:    config,
		cache:     NewMetadataCache(5 * 60), // 5-minute TTL in seconds
	}, nil
}

// GetPodMetadata retrieves pod metadata from K8s API
// ANCHOR: Pod metadata query from K8s API - Phase 2.2, Dec 26, 2025
// Retrieves pod name, namespace, UID, service account, image, and labels
func (c *Client) GetPodMetadata(ctx context.Context, namespace, podName string) (*PodMetadata, error) {
	if namespace == "" || podName == "" {
		return nil, fmt.Errorf("namespace and pod name required")
	}

	// Check cache first
	if cached, found := c.cache.GetPod(namespace, podName); found {
		return cached, nil
	}

	// Query K8s API
	pod, err := c.clientset.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}

	// Extract metadata from pod spec
	image := ""
	if len(pod.Spec.Containers) > 0 {
		image = pod.Spec.Containers[0].Image
	}

	// Create PodMetadata - note: image registry and tag will be parsed by enricher
	metadata := &PodMetadata{
		Name:           pod.Name,
		Namespace:      pod.Namespace,
		UID:            string(pod.UID),
		ServiceAccount: pod.Spec.ServiceAccountName,
		Image:          image,
		ImageRegistry:  "", // Will be parsed by enricher
		ImageTag:       "", // Will be parsed by enricher
		Labels:         pod.Labels,
		OwnerRef:       nil, // TODO: Phase 2.3 - extract owner references from pod
	}

	// Store in cache
	c.cache.SetPod(namespace, podName, metadata)

	return metadata, nil
}

// GetPodByContainerID retrieves pod by container ID
// ANCHOR: Container ID to pod mapping via K8s API - Phase 2.2, Dec 26, 2025
// Normalizes container ID format and queries K8s API to find matching pod
func (c *Client) GetPodByContainerID(ctx context.Context, containerID string) (*PodMetadata, error) {
	if containerID == "" {
		return nil, fmt.Errorf("container ID required")
	}

	// Check mapping cache first
	if mapping, found := c.cache.GetContainerMapping(containerID); found {
		parts := strings.Split(mapping, "/")
		if len(parts) == 2 {
			return c.GetPodMetadata(ctx, parts[0], parts[1])
		}
	}

	// Normalize container ID (strip runtime prefixes)
	normalizedID := c.normalizeContainerID(containerID)

	// Query all pods in all namespaces
	pods, err := c.clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Search for matching container ID
	for _, pod := range pods.Items {
		for _, cs := range pod.Status.ContainerStatuses {
			if c.normalizeContainerID(cs.ContainerID) == normalizedID {
				// Found matching pod, cache the mapping
				mapping := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
				c.cache.SetContainerMapping(containerID, mapping)

				// Query full metadata and return
				return c.GetPodMetadata(ctx, pod.Namespace, pod.Name)
			}
		}
	}

	// Pod not found
	return nil, nil
}

// normalizeContainerID strips runtime prefix from container ID
// Handles docker://, containerd://, cri-o:// prefixes
func (c *Client) normalizeContainerID(containerID string) string {
	prefixes := []string{"docker://", "containerd://", "cri-o://"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(containerID, prefix) {
			return strings.TrimPrefix(containerID, prefix)
		}
	}
	return containerID
}

// GetNodeMetadata retrieves node metadata
// ANCHOR: Node metadata query from K8s API - Phase 2.2, Dec 26, 2025
// Retrieves node name, labels, taints, and resource capacity
func (c *Client) GetNodeMetadata(ctx context.Context, nodeName string) (*NodeMetadata, error) {
	if nodeName == "" {
		return nil, fmt.Errorf("node name required")
	}

	// Check cache first
	if cached, found := c.cache.GetNode(nodeName); found {
		return cached, nil
	}

	// Query K8s API
	node, err := c.clientset.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	// Extract metadata from node spec
	taints := make([]string, 0)
	for _, taint := range node.Spec.Taints {
		taints = append(taints, fmt.Sprintf("%s=%s:%s", taint.Key, taint.Value, taint.Effect))
	}

	capacity := make(map[string]string)
	for k, v := range node.Status.Capacity {
		capacity[k.String()] = v.String()
	}

	metadata := &NodeMetadata{
		Name:     node.Name,
		Labels:   node.Labels,
		Taints:   taints,
		Capacity: capacity,
	}

	// Store in cache
	c.cache.SetNode(nodeName, metadata)

	return metadata, nil
}

// Data structures for Kubernetes metadata
// ANCHOR: PodMetadata and NodeMetadata types used by enrichment - Phase 2.2, Dec 26, 2025
// These types are defined in the kubernetes package to avoid circular imports.
// They are used by both the K8s client and enrichment pipeline.

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

type OwnerReference struct {
	Kind string
	Name string
	UID  string
}

type NodeMetadata struct {
	Name     string
	Labels   map[string]string
	Taints   []string
	Capacity map[string]string
}
