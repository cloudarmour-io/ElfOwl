package network

import "testing"

func TestAddOrUpdateFlowPreservesInitialStateAndDirection(t *testing.T) {
	tracker := NewFlowTracker(0, 100, 1)

	key, created, state := tracker.AddOrUpdateFlow("10.0.0.2", "10.0.0.1", 443, 50000, "tcp", 7, 0, FlowStateESTABLISHED)
	if !created || state != FlowStateESTABLISHED {
		t.Fatalf("new flow = created:%v state:%q, want created:true state:%q", created, state, FlowStateESTABLISHED)
	}
	if got := tracker.GetFlowState(key); got != FlowStateESTABLISHED {
		t.Fatalf("stored state = %q, want %q", got, FlowStateESTABLISHED)
	}

	reverseKey, created, state := tracker.AddOrUpdateFlow("10.0.0.1", "10.0.0.2", 50000, 443, "tcp", 7, 0, FlowStateCLOSING)
	if created || state != FlowStateCLOSING || reverseKey.String() != key.String() {
		t.Fatalf("reverse update = created:%v state:%q key:%q, want existing closing and same key", created, state, reverseKey.String())
	}
	if !tracker.IsReversed(reverseKey) {
		t.Fatal("reverse update was not marked reversed")
	}
}

func TestAddOrUpdateFlowCanonicalizesLoopbackTuple(t *testing.T) {
	tracker := NewFlowTracker(0, 100, 1)
	key, created, _ := tracker.AddOrUpdateFlow("127.0.0.1", "127.0.0.1", 40000, 443, "tcp", 1, 0, FlowStateNEW)
	reverseKey, reverseCreated, _ := tracker.AddOrUpdateFlow("127.0.0.1", "127.0.0.1", 443, 40000, "tcp", 1, 0, FlowStateESTABLISHED)
	if !created || reverseCreated || key.String() != reverseKey.String() {
		t.Fatalf("loopback tuple was not canonicalized: created=%v reverse_created=%v", created, reverseCreated)
	}
}

func TestAddOrUpdateFlowNormalizesIPv6Direction(t *testing.T) {
	tracker := NewFlowTracker(0, 100, 1)
	key, created, _ := tracker.AddOrUpdateFlow("2001:0DB8:0:0::2", "2001:db8::1", 443, 50000, "tcp", 1, 10, FlowStateESTABLISHED)
	if !created {
		t.Fatal("expected initial IPv6 flow")
	}
	reverseKey, created, _ := tracker.AddOrUpdateFlow("2001:DB8::1", "2001:db8::2", 50000, 443, "tcp", 1, 20, FlowStateESTABLISHED)
	if created || reverseKey.String() != key.String() {
		t.Fatal("IPv6 textual variants did not map to the same flow")
	}
	if !tracker.IsReversed(reverseKey) {
		t.Fatal("normalized IPv6 reverse direction was not detected")
	}
}
