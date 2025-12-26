// ANCHOR: CIS Kubernetes v1.8 control rule definitions - Dec 26, 2025
// Defines all 48 automated + 9 manual CIS controls
// IMPLEMENTATION IN PROGRESS - Week 2 task

package rules

// CISControls contains all 57 CIS Kubernetes v1.8 controls
// Breakdown:
// - 48 automated controls (detectable via eBPF + K8s API)
// - 9 manual controls (require node/audit access)

var CISControls = []*Rule{
	// ===== AUTOMATED CONTROLS =====

	// CIS 4.5.1: Minimize the admission of privileged containers
	{
		ControlID:  "CIS_4.5.1",
		Title:      "Minimize the admission of privileged containers",
		Severity:   "CRITICAL",
		EventTypes: []string{"process_execution", "pod_spec_check"},
		Conditions: []Condition{
			{
				Field:    "container.security_context.privileged",
				Operator: "equals",
				Value:    true,
			},
		},
	},

	// CIS 4.5.2: Ensure containers do not run as root
	{
		ControlID:  "CIS_4.5.2",
		Title:      "Ensure containers do not run as root",
		Severity:   "HIGH",
		EventTypes: []string{"process_execution"},
		Conditions: []Condition{
			{
				Field:    "process.uid",
				Operator: "equals",
				Value:    0,
			},
			{
				Field:    "kubernetes.pod_uid",
				Operator: "not_equals",
				Value:    "",
			},
		},
	},

	// CIS 4.5.3: Minimize Linux Kernel Capability usage
	{
		ControlID:  "CIS_4.5.3",
		Title:      "Minimize Linux Kernel Capability usage",
		Severity:   "HIGH",
		EventTypes: []string{"capability_usage"},
		Conditions: []Condition{
			{
				Field:    "capability.name",
				Operator: "in",
				Value: []string{
					"NET_ADMIN", "SYS_ADMIN", "SYS_MODULE",
					"SYS_PTRACE", "SYS_BOOT", "MAC_ADMIN",
				},
			},
		},
	},

	// CIS 4.5.5: Ensure the filesystem is read-only where possible
	{
		ControlID:  "CIS_4.5.5",
		Title:      "Ensure the filesystem is read-only where possible",
		Severity:   "MEDIUM",
		EventTypes: []string{"file_write"},
		Conditions: []Condition{
			{
				Field:    "file.path",
				Operator: "in",
				Value: []string{
					"/", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
					"/etc", "/lib", "/usr/lib",
				},
			},
		},
	},

	// CIS 4.1.1: Ensure ServiceAccount admission controller is enabled
	{
		ControlID:  "CIS_4.1.1",
		Title:      "Ensure ServiceAccount admission controller is enabled",
		Severity:   "HIGH",
		EventTypes: []string{"pod_spec_check"},
		Conditions: []Condition{
			{
				Field:    "kubernetes.service_account",
				Operator: "equals",
				Value:    "default",
			},
		},
	},

	// CIS 4.6.1: Ensure default deny NetworkPolicy is in place
	{
		ControlID:  "CIS_4.6.1",
		Title:      "Ensure default deny NetworkPolicy is in place",
		Severity:   "HIGH",
		EventTypes: []string{"network_policy_check"},
		Conditions: []Condition{
			{
				Field:    "kubernetes.has_default_deny_policy",
				Operator: "not_equals",
				Value:    true,
			},
		},
	},

	// TODO: Week 2 - Add remaining 42 automated controls
	// These include:
	// - Pod security context controls
	// - Network policy controls
	// - RBAC controls
	// - Container image controls
	// - Resource limit controls
	// - And more...

	// ===== MANUAL CONTROLS (Cannot be auto-detected via eBPF) =====
	// These require node access or audit logs:
	// - CIS 1.1.x: API server configuration files
	// - CIS 1.2.x: API server flags
	// - CIS 1.3.x: Controller manager configuration
	// - CIS 1.5.x: etcd encryption
	// - CIS 4.2.x: Kubelet configuration
}

// TODO: Week 2 implementation checklist:
// - [ ] Add 42 more automated control rules
// - [ ] Load rules from ConfigMap in production
// - [ ] Implement rule condition evaluation
// - [ ] Add rule testing with sample events
// - [ ] Add rule documentation with remediation steps
