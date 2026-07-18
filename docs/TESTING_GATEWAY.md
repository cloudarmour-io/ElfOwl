

## Plan: Task #25 - Verify End-to-End with Test Deployment

### Overview
Verify the complete ElfOwl platform works correctly end-to-end using one of the new deployment profiles, ensuring all components (flow tracking, rule matching, enrichment, webhooks) function together.

### Testing Scope

1. **Deploy with Gateway Profile** - Simplest deployment path
   - Load `config/profiles/elf-owl.gateway.yaml`
   - Verify network-behavior rule mode loads correctly
   - Verify bare-metal enrichment backend initializes
   - Test flow tracking with sample network events

2. **Verify Flow Tracking**
   - Generate bidirectional network events (simulated or real)
   - Confirm flows are correlated (same FlowKey for src→dst and dst→src)
   - Verify state transitions (NEW → ESTABLISHED → CLOSING → CLOSED)
   - Check flow closure and metrics emission

3. **Verify Rule Matching**
   - Test network-behavior anomaly rules trigger correctly
   - Verify threshold-based rules (DDoS, port scan, data exfil)
   - Confirm violations/anomalies are logged
   - Check Prometheus metrics (flows_active, anomalies_detected_total, etc.)

4. **Verify Enrichment**
   - Confirm bare-metal enricher populates hostname, process info
   - Verify flow context fields (FlowID, BytesIn/Out, Duration, State)
   - Test with actual network interface if available

5. **Verify Webhook Integration**
   - FlowSummaryEvent is emitted when flows close
   - Webhook pusher can serialize and format events
   - Metrics are recorded for push operations

6. **Optional: Test Kubernetes Profile**
   - If in K8s environment, test compliance mode
   - Verify K8s enrichment loads pod metadata
   - Test CIS control rules match correctly

### Testing Approach

**Manual Testing (Recommended First)**
- Build binary: `go build -o elf-owl cmd/elf-owl/main.go`
- Run with gateway profile: `./elf-owl --config config/profiles/elf-owl.gateway.yaml`
- Monitor logs and Prometheus metrics
- Trigger sample network events (with tcpdump or iperf)
- Verify flow tracking and rule matching in logs

**Integration Testing (Code-Level)**
- Run `go test ./pkg/network/... -v` for flow tracker
- Run `go test ./pkg/rules/... -v` for rule engine
- Run `go test ./pkg/enrichment/backends/... -v` for enrichers
- Check metrics and webhook event serialization

### Success Criteria

- ✅ Agent starts without errors with gateway profile
- ✅ Flow tracker correlates bidirectional events correctly
- ✅ Network-behavior rules match against flows (at least one rule triggers)
- ✅ Metrics are exported (flows_active > 0, anomalies_detected_total incremented)
- ✅ FlowSummaryEvent is emitted and logged
- ✅ No panics or crashes under load
- ✅ All tests pass: `go test ./...`

### Files to Test

- `cmd/elf-owl/main.go` - Agent bootstrap
- `pkg/network/flow_tracker.go` - Flow correlation
- `pkg/rules/engine.go` - Rule matching
- `pkg/enrichment/backends/baremetal_enricher.go` - Enrichment
- `config/profiles/elf-owl.gateway.yaml` - Configuration
- `pkg/metrics/prometheus.go` - Metrics export

### Approval

Please review and approve before I proceed with end-to-end verification testing.
