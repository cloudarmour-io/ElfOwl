// ANCHOR: Event enrichment data structures - Dec 26, 2025
// Defines enriched event types with Kubernetes and container context

package enrichment

import (
	"time"

	"github.com/udyansh/elf-owl/pkg/kubernetes"
)

// EnrichedEvent is an event with added K8s, container, and runtime context
type EnrichedEvent struct {
	// Original cilium/ebpf event (interface{} to avoid circular import)
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

	// Network and DNS context
	Network *NetworkContext `json:"network"`
	DNS     *DNSContext     `json:"dns"`
	TLS     *TLSContext     `json:"tls"`

	// Derived fields
	Timestamp  time.Time `json:"timestamp"`
	Severity   string    `json:"severity"`
	CISControl string    `json:"cis_control"`
}

// K8sContext contains Kubernetes metadata
type K8sContext struct {
	ClusterID                    string            `json:"cluster_id"`
	NodeName                     string            `json:"node_name"`
	Namespace                    string            `json:"namespace"`
	PodName                      string            `json:"pod_name"`
	PodUID                       string            `json:"pod_uid"`
	ServiceAccount               string            `json:"service_account"`
	Image                        string            `json:"image"`
	ImageRegistry                string            `json:"image_registry"`
	ImageTag                     string            `json:"image_tag"`
	Labels                       map[string]string `json:"labels"`
	OwnerRef                     *OwnerReference   `json:"owner_ref"`
	AutomountServiceAccountToken bool              `json:"automount_service_account_token"`
	HasDefaultDenyNetworkPolicy  bool              `json:"has_default_deny_network_policy"`
	// ANCHOR: Extended K8s fields for Phase 1 RBAC controls - Dec 26, 2025
	RBACEnforced              bool  `json:"rbac_enforced"`
	RBACLevel                 int   `json:"rbac_level"`
	ServiceAccountTokenAge    int64 `json:"service_account_token_age"`
	ServiceAccountPermissions int   `json:"service_account_permissions"`
	RBACPolicyDefined         bool  `json:"rbac_policy_defined"`
	RolePermissionCount       int   `json:"role_permission_count"`
	AuditLoggingEnabled       bool  `json:"audit_logging_enabled"`
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
	// ANCHOR: Extended security context fields for Phase 1 - Dec 26, 2025
	AllowPrivilegeEscalation      bool   `json:"allow_privilege_escalation"`
	AllowPrivilegeEscalationKnown bool   `json:"allow_privilege_escalation_known"`
	HostNetwork                   bool   `json:"host_network"`
	HostIPC                       bool   `json:"host_ipc"`
	HostPID                       bool   `json:"host_pid"`
	SeccompProfile                string `json:"seccomp_profile"`
	ApparmorProfile               string `json:"apparmor_profile"`
	SELinuxLevel                  string `json:"selinux_level"`
	ImagePullPolicy               string `json:"image_pull_policy"`
	ImageScanStatus               string `json:"image_scan_status"`
	ImageRegistryAuth             bool   `json:"image_registry_auth"`
	ImageSigned                   bool   `json:"image_signed"`
	MemoryLimit                   string `json:"memory_limit"`
	CPULimit                      string `json:"cpu_limit"`
	MemoryRequest                 string `json:"memory_request"`
	CPURequest                    string `json:"cpu_request"`
	StorageRequest                string `json:"storage_request"`
	ReadOnlyFilesystem            bool   `json:"read_only_filesystem"`
	VolumeType                    string `json:"volume_type"`
	IsolationLevel                int    `json:"isolation_level"`
	KernelHardening               bool   `json:"kernel_hardening"`
}

// ProcessContext captures process metadata from cilium/ebpf events
// ANCHOR: Process context extensions - Feature: parent PID + arguments - Jan 2026
// Adds parent PID and argument list for richer forensic context.
type ProcessContext struct {
	PID         uint32   `json:"pid"`
	ParentPID   uint32   `json:"parent_pid"`
	UID         uint32   `json:"uid"`
	GID         uint32   `json:"gid"`
	Command     string   `json:"command"`
	Arguments   []string `json:"arguments"`
	Filename    string   `json:"filename"`
	ContainerID string   `json:"container_id"`
}

// FileContext captures file metadata from cilium/ebpf events
// ANCHOR: File context extensions - Feature: mode + sensitive path - Mar 24, 2026
// Adds mode and sensitivity flags for expanded file operation coverage.
type FileContext struct {
	Path      string `json:"path"`
	Operation string `json:"operation"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	Mode      uint32 `json:"mode"`
	FD        uint32 `json:"fd"`
	Sensitive bool   `json:"sensitive"`
}

// CapabilityContext captures capability usage metadata
// ANCHOR: Capability context extension - Feature: syscall attribution - Mar 24, 2026
// Surfaces syscall IDs associated with capability checks.
type CapabilityContext struct {
	Name      string `json:"name"`
	Allowed   bool   `json:"allowed"`
	PID       uint32 `json:"pid"`
	UID       uint32 `json:"uid"`
	SyscallID uint32 `json:"syscall_id"`
}

// Note: PodMetadata and NodeMetadata are defined in kubernetes package
// to avoid circular imports. We import and re-export them here for convenience.

// Type aliases to kubernetes types to avoid duplication
type PodMetadata = kubernetes.PodMetadata
type NodeMetadata = kubernetes.NodeMetadata

// ANCHOR: Network and DNS contexts for Phase 1 - Dec 26, 2025
// Support for network policy and DNS rule matching

// NetworkContext captures environment-agnostic network metadata
// ANCHOR: Environment-agnostic network context - Feature: network-behavior-centric core - Jul 18, 2026
// Minimal, cross-environment fields for network behavior analysis.
// Optional SourceEnrichment/DestEnrichment holds environment-specific context (K8s pod, bare-metal hostname, etc.)
type NetworkContext struct {
	// Core network tuple (environment-agnostic)
	SourceIP           string `json:"source_ip"`
	DestinationIP      string `json:"destination_ip"`
	SourcePort         uint16 `json:"source_port"`
	DestinationPort    uint16 `json:"destination_port"`
	Protocol           string `json:"protocol"`
	Direction          string `json:"direction"` // inbound, outbound
	ConnectionState    string `json:"connection_state"`
	NetworkNamespaceID uint32 `json:"network_namespace_id"`
	IngressRestricted  bool   `json:"ingress_restricted"`
	EgressRestricted   bool   `json:"egress_restricted"`
	NamespaceIsolation bool   `json:"namespace_isolation"`

	// Flow tracking (cross-environment)
	// ANCHOR: Flow-level enrichment - Feature: bidirectional conntrack-style correlation - Jul 18, 2026
	// FlowID uniquely identifies bidirectional flow (same for src→dst and dst→src events)
	// FlowStartTime allows calculation of flow duration for anomaly detection (e.g., > 24h tunnel)
	// BytesIn/BytesOut track per-direction traffic for data exfiltration detection
	// StateTransition describes state machine progression (NEW_TO_ESTABLISHED, etc.)
	// IsReversed indicates this event is the reverse direction of an established flow
	FlowID             string `json:"flow_id,omitempty"`             // hash of canonical flow key
	FlowStartTime      int64  `json:"flow_start_time,omitempty"`     // Unix timestamp when flow created
	FlowDuration       int64  `json:"flow_duration_seconds,omitempty"` // derived from now - flow_start_time
	BytesIn            uint64 `json:"bytes_in,omitempty"`            // bytes received (reverse direction)
	BytesOut           uint64 `json:"bytes_out,omitempty"`           // bytes sent (forward direction)
	PacketsIn          uint64 `json:"packets_in,omitempty"`
	PacketsOut         uint64 `json:"packets_out,omitempty"`
	StateTransition    string `json:"state_transition,omitempty"`    // e.g., "NEW_TO_ESTABLISHED", "ESTABLISHED_TO_CLOSING"
	IsReversed         bool   `json:"is_reversed,omitempty"`         // true if reverse direction of flow

	// Optional environment-specific enrichment (populated by active backend)
	// ANCHOR: Pluggable enrichment context - Feature: environment-agnostic core - Jul 18, 2026
	// SourceEnrichment/DestEnrichment hold backend-specific context:
	// - K8s: pod name, namespace, service account, RBAC level
	// - Bare-metal: hostname, process, user, SELinux context
	// - Cloud: instance ID, tags, IAM role
	SourceEnrichment      interface{} `json:"source_enrichment,omitempty"`  // *BareMetalSourceContext or *K8sSourceContext
	DestinationEnrichment interface{} `json:"dest_enrichment,omitempty"`
}

// BareMetalSourceContext captures host and process context for bare-metal/VM/gateway networks
// ANCHOR: Bare-metal network enrichment - Feature: hostname, process, OS context - Jul 18, 2026
// Enriches network flows with host metadata, process info, and security context.
// Used on gateways, bare-metal servers, and VMs without Kubernetes.
type BareMetalSourceContext struct {
	Hostname        string `json:"hostname"`                 // Resolved hostname (reverse DNS or local)
	ProcessName     string `json:"process_name,omitempty"`   // Executable name
	ProcessPID      uint32 `json:"process_pid,omitempty"`    // Process ID
	User            string `json:"user,omitempty"`           // Process owner username
	UID             uint32 `json:"uid,omitempty"`            // Numeric UID
	GID             uint32 `json:"gid,omitempty"`            // Numeric GID
	SELinuxContext  string `json:"selinux_context,omitempty"`  // SELinux label
	SecurityProfile string `json:"security_profile,omitempty"` // AppArmor, SELinux, etc.
}

// K8sSourceContext captures Kubernetes-specific context for network flows
// ANCHOR: Kubernetes network enrichment - Feature: optional K8s context - Jul 18, 2026
// Enriches network flows with pod, service account, RBAC, and network policy context.
// Used when elf-owl runs as K8s DaemonSet or when monitoring K8s cluster traffic.
type K8sSourceContext struct {
	Namespace              string `json:"namespace,omitempty"`
	PodName                string `json:"pod_name,omitempty"`
	PodUID                 string `json:"pod_uid,omitempty"`
	ServiceAccount         string `json:"service_account,omitempty"`
	Labels                 map[string]string `json:"labels,omitempty"`
	RBACLevel              int    `json:"rbac_level,omitempty"`
	RBACEnforced           bool   `json:"rbac_enforced,omitempty"`
	ServiceAccountTokenAge int64  `json:"service_account_token_age,omitempty"`
}

// DNSContext captures DNS query metadata from cilium/ebpf events
type DNSContext struct {
	QueryName      string   `json:"query_name"`
	QueryType      string   `json:"query_type"` // A, AAAA, MX, etc.
	ResponseCode   int      `json:"response_code"`
	QueryAllowed   bool     `json:"query_allowed"`
	AllowedDomains []string `json:"allowed_domains"`
}

// TLSContext captures TLS ClientHello metadata and JA3 fingerprinting output.
type TLSContext struct {
	JA3Fingerprint string   `json:"ja3_fingerprint"`
	JA3String      string   `json:"ja3_string"`
	TLSVersion     string   `json:"tls_version"`
	Ciphers        []uint16 `json:"ciphers"`
	Extensions     []uint16 `json:"extensions"`
	Curves         []uint16 `json:"curves"`
	PointFormats   []uint8  `json:"point_formats"`
	SNI            string   `json:"sni,omitempty"`
	// ANCHOR: TLS certificate fields - Feature: cert_sha256 via active probe - Apr 26, 2026
	// Populated by userspace TLS probe to host:443 after SNI is known, matching vaanvil approach.
	CertSHA256  string `json:"cert_sha256,omitempty"`
	CertIssuer  string `json:"cert_issuer,omitempty"`
	CertExpiry  int64  `json:"cert_expiry,omitempty"`
}
