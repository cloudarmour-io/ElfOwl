module github.com/udyansh/elf-owl

go 1.23

require (
	// Direct goBPF import for eBPF monitoring
	github.com/udyansh/gobpf v0.1.0

	// Kubernetes client for metadata
	k8s.io/client-go v0.29.0
	k8s.io/apimachinery v0.29.0

	// Cryptography for signing and encryption
	golang.org/x/crypto v0.40.0

	// HTTP client for Owl API
	github.com/go-resty/resty/v2 v2.11.0

	// Logging
	go.uber.org/zap v1.27.0

	// Metrics
	github.com/prometheus/client_golang v1.18.0

	// Configuration
	github.com/spf13/viper v1.18.2

	// YAML parsing
	gopkg.in/yaml.v3 v3.0.1

	// UUID generation
	github.com/google/uuid v1.6.0
)
