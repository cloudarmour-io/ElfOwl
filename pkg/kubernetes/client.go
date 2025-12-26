// ANCHOR: Kubernetes API client - Dec 26, 2025
// Provides read-only K8s API access for metadata enrichment
// IMPLEMENTATION IN PROGRESS - Week 4 task

package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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
func (c *Client) GetPodMetadata(ctx context.Context, namespace, podName string) (*PodMetadata, error) {
	// TODO: Week 4 implementation
	// 1. Check cache first
	// 2. Query K8s API if not cached
	// 3. Store in cache
	// 4. Return metadata

	return nil, fmt.Errorf("not yet implemented")
}

// GetPodByContainerID retrieves pod by container ID
func (c *Client) GetPodByContainerID(ctx context.Context, containerID string) (*PodMetadata, error) {
	// TODO: Week 4 implementation
	// 1. Query all pods across all namespaces
	// 2. Match container ID from cgroup
	// 3. Return pod metadata

	return nil, fmt.Errorf("not yet implemented")
}

// GetNodeMetadata retrieves node metadata
func (c *Client) GetNodeMetadata(ctx context.Context, nodeName string) (*NodeMetadata, error) {
	// TODO: Week 4 implementation

	return nil, fmt.Errorf("not yet implemented")
}

// Data structures matching enrichment types
type PodMetadata struct {
	Name           string
	Namespace      string
	UID            string
	ServiceAccount string
	Image          string
	ImageRegistry  string
	ImageTag       string
	Labels         map[string]string
}

type NodeMetadata struct {
	Name     string
	Labels   map[string]string
	Taints   []string
	Capacity map[string]string
}
