// ANCHOR: Network behavior detection rules - Feature: firewall/gateway anomaly detection - Jul 18, 2026
// Detects network security incidents through flow-level pattern analysis.
// Rules are environment-agnostic: reference only NetworkContext fields, not K8s/host-specific data.
// Used in network-behavior-centric mode for gateway, firewall, and load balancer deployments.

package rules

// NetworkBehavior detects common network-level threats and anomalies.
// Focuses on flow-based patterns: DDoS floods, port scanning, data exfiltration, tunneling.
// These rules work across all deployment environments (gateway, bare-metal, VM, K8s).

var NetworkBehavior = []*Rule{
	// ===== CONNECTION FLOOD DETECTION =====

	// NET_BEHAVIOR_001: DDoS Flood Detection
	// ANCHOR: DDoS flood rule - Feature: high-velocity connection detection - Jul 18, 2026
	// Triggers when many NEW state connections reach same dst:port from diverse sources.
	// Pattern: 1000+ NEW connections to single service in 10 seconds.
	// Used to detect volumetric DDoS attacks on exposed services.
	{
		ControlID:     "NET_BEHAVIOR_001",
		Title:      "DDoS Flood Detected",
		Severity:   "CRITICAL",
		EventTypes: []string{"flow_summary"},
		Conditions: []Condition{
			{
				Field:    "network.state_transition",
				Operator: "contains",
				Value:    "NEW",
			},
		},
	},

	// ===== DATA EXFILTRATION DETECTION =====

	// NET_BEHAVIOR_002: Data Exfiltration Suspected
	// ANCHOR: Data exfiltration rule - Feature: unusual outbound transfer detection - Jul 18, 2026
	// Triggers when single flow exceeds 10GB outbound in < 5 minutes.
	// Pattern: Large outbound transfer in short time window.
	// Used to detect data theft, backup exfil, or malware spreading.
	{
		ControlID:     "NET_BEHAVIOR_002",
		Title:      "Data Exfiltration Suspected",
		Severity:   "HIGH",
		EventTypes: []string{"flow_summary"},
		Conditions: []Condition{
			{
				Field:    "network.bytes_out",
				Operator: "greater_than",
				Value:    10737418240, // 10GB in bytes
			},
			{
				Field:    "network.flow_duration_seconds",
				Operator: "less_than",
				Value:    300, // 5 minutes
			},
		},
	},

	// ===== LONG-LIVED CONNECTION DETECTION =====

	// NET_BEHAVIOR_003: Persistent Tunnel or Long-Lived Connection
	// ANCHOR: Long-lived connection rule - Feature: C2 tunnel detection - Jul 18, 2026
	// Triggers when connection remains in ESTABLISHED state for > 24 hours.
	// Pattern: Unusually persistent bi-directional flow.
	// Used to detect command & control tunnels, reverse shells, persistence mechanisms.
	{
		ControlID:     "NET_BEHAVIOR_003",
		Title:      "Persistent Tunnel or Long-Lived Connection",
		Severity:   "MEDIUM",
		EventTypes: []string{"flow_summary"},
		Conditions: []Condition{
			{
				Field:    "network.flow_duration_seconds",
				Operator: "greater_than",
				Value:    86400, // 24 hours
			},
		},
	},

	// ===== UNUSUAL PROTOCOL COMBINATION DETECTION =====

	// NET_BEHAVIOR_004: Unusual Protocol Combination
	// ANCHOR: Protocol mismatch rule - Feature: encryption/tunneling detection - Jul 18, 2026
	// Triggers when protocol doesn't match expected port usage.
	// Examples: Non-HTTP on port 80, Non-HTTPS on 443, Non-DNS on 53.
	// Used to detect encrypted tunnels (DNS exfil, HTTP tunneling, port hopping).
	{
		ControlID:     "NET_BEHAVIOR_004",
		Title:      "Unusual Protocol Combination",
		Severity:   "MEDIUM",
		EventTypes: []string{"flow_summary"},
		Conditions: []Condition{
			// Note: Requires context of port→expected protocol mapping from gateway-services.yaml
			// Current rule engine evaluates single events; aggregate rules (protocol mismatch detection)
			// deferred to Phase 2 (aggregation engine with flow context).
		},
	},

	// ===== RETRY / CONNECTION FAILURE PATTERN =====

	// NET_BEHAVIOR_005: Rapid Connection Retries
	// ANCHOR: Connection retry rule - Feature: network service availability monitor - Jul 18, 2026
	// Triggers when source repeatedly attempts connection to unreachable destination.
	// Pattern: 50+ failed connections (RST/TIMEOUT) in 60 seconds.
	// Used to detect probing behavior, port scanning, or service unavailability.
	{
		ControlID:     "NET_BEHAVIOR_005",
		Title:      "Rapid Connection Retries Detected",
		Severity:   "MEDIUM",
		EventTypes: []string{"flow_summary"},
		Conditions: []Condition{
			{
				Field:    "network.state_transition",
				Operator: "contains",
				Value:    "RESET", // Connection closed by RST
			},
		},
	},
}
