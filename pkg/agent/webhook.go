// ANCHOR: Inbound webhook handler - Feature: typed event ingestion endpoint - Apr 29, 2026
// Accepts POST /webhook/events with {type, payload, timestamp} envelope.
// Routes by EventType to the matching enricher; same pipeline as eBPF-sourced events.

package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/enrichment"
)

// EventType identifies the kind of security event carried in a WebhookEnvelope.
type EventType string

const (
	EventTypeProcess    EventType = "process"
	EventTypeNetwork    EventType = "network"
	EventTypeDNS        EventType = "dns"
	EventTypeFile       EventType = "file"
	EventTypeCapability EventType = "capability"
	EventTypeTLS        EventType = "tls"
)

// valid reports whether t is a recognised EventType.
func (t EventType) valid() bool {
	switch t {
	case EventTypeProcess, EventTypeNetwork, EventTypeDNS,
		EventTypeFile, EventTypeCapability, EventTypeTLS:
		return true
	}
	return false
}

// WebhookEnvelope is the JSON body expected by POST /webhook/events.
// The type field determines how payload is enriched and which rules are evaluated.
type WebhookEnvelope struct {
	Type      EventType       `json:"type"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp time.Time       `json:"timestamp"`
}

// WebhookResponse is the JSON body returned on a successful ingest.
type WebhookResponse struct {
	Accepted bool      `json:"accepted"`
	Type     EventType `json:"type"`
}

// WebhookHandler returns an http.Handler for the /webhook/events endpoint.
// The handler is safe for concurrent use.
func (a *Agent) WebhookHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		maxBytes := a.Config.Agent.Webhook.MaxPayloadBytes
		if maxBytes <= 0 {
			maxBytes = 1048576
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

		var env WebhookEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			http.Error(w, fmt.Sprintf("invalid json: %v", err), http.StatusBadRequest)
			return
		}

		if !env.Type.valid() {
			http.Error(w, fmt.Sprintf("unknown event type %q; accepted: process, network, dns, file, capability, tls", env.Type), http.StatusBadRequest)
			return
		}

		if env.Timestamp.IsZero() {
			env.Timestamp = time.Now()
		}

		a.Logger.Debug("webhook event received",
			zap.String("type", string(env.Type)),
			zap.Time("timestamp", env.Timestamp),
		)

		// Build a minimal pre-enriched event carrying the raw JSON payload.
		// The enricher adds K8s context; if not available the pipeline honours kubernetes_only.
		raw := &enrichment.EnrichedEvent{
			EventType: string(env.Type),
			RawEvent:  env.Payload,
			Timestamp: env.Timestamp,
		}

		enrichFn, ok := a.webhookEnrichFn(env.Type)
		if !ok {
			// Should never happen — already validated above.
			http.Error(w, "no enricher for type", http.StatusInternalServerError)
			return
		}

		a.handleRuntimeEvent(
			r.Context(),
			raw,
			enrichFn,
			fmt.Sprintf("discarded webhook %s event: no pod context", env.Type),
			fmt.Sprintf("processing webhook %s event (kubernetes_only disabled)", env.Type),
			fmt.Sprintf("discarded webhook %s event: K8s lookup failed", env.Type),
			fmt.Sprintf("webhook %s event enrichment failed, using partial event", env.Type),
			false,
		)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(WebhookResponse{Accepted: true, Type: env.Type})
	})
}

// webhookEnrichFn returns the enricher function that matches the given EventType.
func (a *Agent) webhookEnrichFn(t EventType) (func(context.Context, interface{}) (*enrichment.EnrichedEvent, error), bool) {
	switch t {
	case EventTypeProcess:
		return a.Enricher.EnrichProcessEvent, true
	case EventTypeNetwork:
		return a.Enricher.EnrichNetworkEvent, true
	case EventTypeDNS:
		return a.Enricher.EnrichDNSEvent, true
	case EventTypeFile:
		return a.Enricher.EnrichFileEvent, true
	case EventTypeCapability:
		return a.Enricher.EnrichCapabilityEvent, true
	case EventTypeTLS:
		return a.Enricher.EnrichTLSEvent, true
	}
	return nil, false
}
