package ebpf

// ANCHOR: IPProtoName - Feature: network protocol filter - May 1, 2026
// Single source of truth for IPPROTO number → string name used by the network
// monitor's early-exit filter and by enricher.go's protocolName helper.
// Covers all protocols that can appear from inet_sock_set_state, tcp_connect,
// and sys_enter_sendto hooks, plus common protocols for future hook additions.
func IPProtoName(proto uint8) string {
	switch proto {
	case 1:
		return "icmp"
	case 2:
		return "igmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 33:
		return "dccp"
	case 41:
		return "ipv6"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 51:
		return "ah"
	case 58:
		return "icmpv6"
	case 89:
		return "ospf"
	case 103:
		return "pim"
	case 112:
		return "vrrp"
	case 132:
		return "sctp"
	case 136:
		return "udplite"
	default:
		return "unknown"
	}
}
