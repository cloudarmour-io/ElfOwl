// ANCHOR: TCP State Constants and Mapping - Feature: kernel state transitions - Jul 22, 2026
// Maps kernel TCP states to ElfOwl 4-state flow machine for accurate connection tracking

package network

// TCP state constants (from Linux kernel include/net/tcp_states.h)
const (
	TCPEstablished = 1
	TCPSynSent     = 2
	TCPSynRecv     = 3
	TCPFinWait1    = 4
	TCPFinWait2    = 5
	TCPTimeWait    = 6
	TCPClose       = 7
	TCPCloseWait   = 8
	TCPLastAck     = 9
	TCPListen      = 10
	TCPClosing     = 11
)

// TCPStateToFlowState maps kernel TCP states to our simplified flow state machine
// ANCHOR: TCP to Flow State Mapping - Feature: kernel state tracking - Jul 22, 2026
// Maps kernel TCP states to 4-state machine:
//   - NEW: SYN_SENT, SYN_RECV (connection setup)
//   - ESTABLISHED: bidirectional data flow
//   - CLOSING: FIN_WAIT*, CLOSE_WAIT, LAST_ACK (graceful shutdown)
//   - CLOSED: TIME_WAIT, CLOSE (fully terminated)
func TCPStateToFlowState(tcpState uint32) FlowState {
	switch tcpState {
	case TCPSynSent, TCPSynRecv:
		return FlowStateNEW
	case TCPEstablished:
		return FlowStateESTABLISHED
	case TCPFinWait1, TCPFinWait2, TCPCloseWait, TCPLastAck, TCPClosing:
		return FlowStateCLOSING
	case TCPTimeWait, TCPClose:
		return FlowStateCLOSED
	case TCPListen:
		return ""  // Ignore server listening sockets
	default:
		return ""  // Unknown state
	}
}

// ANCHOR: ConnectionState name to FlowState mapping - Bug: flows stuck at "new" - Aug 14, 2026
// pkg/agent/agent.go previously cast NetworkContext.ConnectionState (an uppercase kernel
// state name like "ESTABLISHED", produced by network_monitor.go's tcpStateName) directly to
// FlowState via network.FlowState(name). FlowState constants are lowercase ("established",
// "new", ...), so that cast never matched a real constant and stored the raw kernel name into
// flow.State instead of transitioning the 4-state machine. FlowStateFromName translates the
// display name to the correct FlowState, returning "" for names that carry no meaningful
// transition (LISTEN, UNKNOWN, "") so callers can leave an existing flow's state untouched.
func FlowStateFromName(name string) FlowState {
	switch name {
	case "SYN_SENT", "SYN_RECV", "NEW_SYN_RECV":
		return FlowStateNEW
	case "ESTABLISHED":
		return FlowStateESTABLISHED
	case "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT", "LAST_ACK", "CLOSING":
		return FlowStateCLOSING
	case "TIME_WAIT", "CLOSE":
		return FlowStateCLOSED
	default: // LISTEN, UNKNOWN, ""
		return ""
	}
}

// TCPStateName returns human-readable name for TCP state constant
func TCPStateName(state uint32) string {
	switch state {
	case TCPEstablished:
		return "ESTABLISHED"
	case TCPSynSent:
		return "SYN_SENT"
	case TCPSynRecv:
		return "SYN_RECV"
	case TCPFinWait1:
		return "FIN_WAIT1"
	case TCPFinWait2:
		return "FIN_WAIT2"
	case TCPTimeWait:
		return "TIME_WAIT"
	case TCPClose:
		return "CLOSE"
	case TCPCloseWait:
		return "CLOSE_WAIT"
	case TCPLastAck:
		return "LAST_ACK"
	case TCPListen:
		return "LISTEN"
	case TCPClosing:
		return "CLOSING"
	default:
		return "UNKNOWN"
	}
}

// FlowStateName returns human-readable name for flow state
func FlowStateName(state FlowState) string {
	switch state {
	case FlowStateNEW:
		return "NEW"
	case FlowStateESTABLISHED:
		return "ESTABLISHED"
	case FlowStateCLOSING:
		return "CLOSING"
	case FlowStateCLOSED:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}
