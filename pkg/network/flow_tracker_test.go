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
