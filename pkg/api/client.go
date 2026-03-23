// ANCHOR: Owl SaaS push-only API client - Dec 26, 2025
// Pushes signed/encrypted evidence to Owl SaaS (one-way outbound only)

package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"

	"github.com/udyansh/elf-owl/pkg/config"
	"github.com/udyansh/elf-owl/pkg/evidence"
)

// Client provides push-only communication with Owl SaaS
// INVARIANT: This client can ONLY push evidence, never receives commands
type Client struct {
	endpoint      string
	clusterID     string
	nodeName      string
	jwtToken      string
	httpClient    *resty.Client
	logger        *zap.Logger
	signer        *evidence.Signer
	cipher        *evidence.Cipher
	tlsConfig     *tls.Config
	retryConfig   config.RetryConfig

	// Metrics (thread-safe with mutex)
	mu              sync.Mutex
	lastPushTime    time.Time
	failureCount    int64
	successCount    int64
}

// NewClient creates a new Owl API client
//
// ANCHOR: NewClient with TLS wiring - Findings Note - Feb 18, 2026
// WHY: TLSConfig was stored in agent config but never applied to the HTTP client,
//      causing all pushes to ignore CA cert verification and client certs.
// WHAT: Accept a *tls.Config built by the caller and apply it to the resty client
//       so that CACertPath, client cert/key, and InsecureSkipVerify are honoured.
// HOW: Caller (agent.go) reads TLS files from disk and constructs *tls.Config;
//      we apply it via resty.SetTLSClientConfig. Nil means use system defaults.
func NewClient(
	endpoint string,
	clusterID string,
	nodeName string,
	jwtToken string,
	signer *evidence.Signer,
	cipher *evidence.Cipher,
	tlsCfg *tls.Config,
	retryConfig config.RetryConfig,
) (*Client, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	if clusterID == "" {
		return nil, fmt.Errorf("cluster_id is required")
	}

	if nodeName == "" {
		return nil, fmt.Errorf("node_name is required")
	}

	logger, _ := zap.NewProduction()

	rc := resty.New()
	if tlsCfg != nil {
		rc.SetTLSClientConfig(tlsCfg)
	}

	return &Client{
		endpoint:    endpoint,
		clusterID:   clusterID,
		nodeName:    nodeName,
		jwtToken:    jwtToken,
		httpClient:  rc,
		logger:      logger,
		signer:      signer,
		cipher:      cipher,
		tlsConfig:   tlsCfg,
		retryConfig: retryConfig,
	}, nil
}

// BuildTLSConfig constructs a *tls.Config from the agent's TLS settings.
// Returns nil (use system defaults) when TLS is disabled or no custom certs
// are configured. Called by agent.go to avoid a circular package import.
//
// ANCHOR: BuildTLSConfig helper - Findings Note - Feb 18, 2026
// WHY: api package cannot import agent package (circular); agent package builds
//      the *tls.Config using this helper which only takes primitive values.
// WHAT: Load CA cert, client cert/key from disk; build *tls.Config.
// HOW: Uses crypto/x509 and crypto/tls from stdlib; no external deps.
func BuildTLSConfig(enabled, verify bool, caCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	if !enabled {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: !verify, //nolint:gosec // controlled by operator config
	}

	if caCertPath != "" {
		caPEM, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", caCertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA cert %s", caCertPath)
		}
		tlsCfg.RootCAs = pool
	}

	if clientCertPath != "" && clientKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// PushBatch is the plaintext JSON payload before encryption.
// It is signed (HMAC-SHA256) before being encrypted.
type PushBatch struct {
	ClusterID string                    `json:"cluster_id"`
	NodeName  string                    `json:"node_name"`
	Events    []*evidence.BufferedEvent `json:"events"`
	Signature string                    `json:"signature"`
	SentAt    time.Time                 `json:"sent_at"`
}

// EncryptedEnvelope is the outer JSON wrapper sent over the wire when encryption
// is enabled. The server decrypts ciphertext using nonce, then verifies the
// HMAC signature inside the plaintext PushBatch.
type EncryptedEnvelope struct {
	Encrypted  bool   `json:"encrypted"`
	Ciphertext string `json:"ciphertext"` // base64-encoded AES-256-GCM ciphertext
	Nonce      string `json:"nonce"`      // base64-encoded 12-byte GCM nonce
}

// Push sends buffered events to Owl SaaS (single attempt).
//
// ANCHOR: Implement event push: JSON+sign+encrypt+gzip+HTTP POST - Feb 18, 2026 / Fixed Feb 18, 2026
// WHY: Previously returned "not yet implemented". Second pass wires AES-256-GCM
//      encryption that was committed but never called (Critical finding).
// WHAT: Sign plaintext JSON with HMAC-SHA256, encrypt the signed JSON with
//       AES-256-GCM, wrap in EncryptedEnvelope, gzip, POST.
// HOW:  1. Marshal PushBatch to JSON
//       2. Sign raw JSON → embed signature → re-marshal (sign-then-encrypt)
//       3. If cipher present: Encrypt(signedJSON) → base64(ciphertext+nonce)
//          wrapped in EncryptedEnvelope → marshal envelope
//          If no cipher: send signed JSON directly (dev/test mode)
//       4. gzip compress final payload
//       5. POST with Authorization, Content-Encoding, X-Encrypted headers
//       6. Accept HTTP 200/202; anything else is an error
func (c *Client) Push(ctx context.Context, bufferedEvents []*evidence.BufferedEvent) error {
	if len(bufferedEvents) == 0 {
		return nil
	}

	c.logger.Debug("push: serialising events",
		zap.Int("count", len(bufferedEvents)),
	)

	// Step 1: Build batch payload
	batch := &PushBatch{
		ClusterID: c.clusterID,
		NodeName:  c.nodeName,
		Events:    bufferedEvents,
		SentAt:    time.Now().UTC(),
	}

	// Step 2: Marshal to JSON
	rawJSON, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("push: marshal batch: %w", err)
	}

	// Step 3: Sign the raw JSON for integrity verification by Owl SaaS.
	// We sign BEFORE encryption (sign-then-encrypt) so the server can verify
	// integrity after decryption without needing a second round-trip.
	if c.signer != nil {
		batch.Signature = c.signer.Sign(rawJSON)
		// Re-marshal with signature embedded in the batch
		rawJSON, err = json.Marshal(batch)
		if err != nil {
			return fmt.Errorf("push: marshal signed batch: %w", err)
		}
	}

	// Step 4: Encrypt the signed JSON with AES-256-GCM.
	// ANCHOR: AES-256-GCM encryption of push payload - Critical finding fix - Feb 18, 2026
	// WHY: Cipher was stored in Client struct but never called; evidence was sent
	//      in plaintext over the wire violating the AES-256-GCM requirement.
	// WHAT: Encrypt signed JSON → wrap ciphertext+nonce in EncryptedEnvelope.
	// HOW:  cipher.Encrypt() returns (ciphertext, nonce) separately; both are
	//       base64-encoded and packed into the envelope so the server can decrypt.
	var wirePayload []byte
	encrypted := false
	if c.cipher != nil {
		ciphertext, nonce, err := c.cipher.Encrypt(rawJSON)
		if err != nil {
			return fmt.Errorf("push: encrypt payload: %w", err)
		}
		envelope := &EncryptedEnvelope{
			Encrypted:  true,
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
		}
		wirePayload, err = json.Marshal(envelope)
		if err != nil {
			return fmt.Errorf("push: marshal envelope: %w", err)
		}
		encrypted = true
	} else {
		// No cipher configured: send signed JSON directly (dev/test mode only)
		wirePayload = rawJSON
	}

	// Step 5: gzip compress the wire payload
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(wirePayload); err != nil {
		return fmt.Errorf("push: gzip write: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("push: gzip close: %w", err)
	}

	// Step 6: POST to Owl SaaS
	encryptedHeader := "false"
	if encrypted {
		encryptedHeader = "true"
	}
	url := c.endpoint + "/api/v1/evidence"
	resp, err := c.httpClient.R().
		SetContext(ctx).
		SetHeader("Content-Type", "application/json").
		SetHeader("Content-Encoding", "gzip").
		SetHeader("Authorization", "Bearer "+c.jwtToken).
		SetHeader("X-Cluster-ID", c.clusterID).
		SetHeader("X-Node-Name", c.nodeName).
		SetHeader("X-Encrypted", encryptedHeader).
		SetBody(buf.Bytes()).
		Post(url)

	if err != nil {
		return fmt.Errorf("push: http post: %w", err)
	}

	if resp.StatusCode() != http.StatusOK && resp.StatusCode() != http.StatusAccepted {
		return fmt.Errorf("push: unexpected status %d: %s", resp.StatusCode(), resp.String())
	}

	c.logger.Debug("push: succeeded",
		zap.Int("events", len(bufferedEvents)),
		zap.Int("compressedBytes", buf.Len()),
		zap.Bool("encrypted", encrypted),
		zap.Int("statusCode", resp.StatusCode()),
	)

	return nil
}

// PushWithRetry sends events with exponential backoff retry
func (c *Client) PushWithRetry(ctx context.Context, bufferedEvents []*evidence.BufferedEvent) error {
	if len(bufferedEvents) == 0 {
		return nil
	}

	backoff := c.retryConfig.InitialBackoff

	for attempt := 0; attempt < c.retryConfig.MaxRetries; attempt++ {
		err := c.Push(ctx, bufferedEvents)
		if err == nil {
			// ANCHOR: Update metrics on successful push with mutex protection - Dec 26, 2025
			// Use mutex to safely update lastPushTime and successCount
			c.mu.Lock()
			c.lastPushTime = time.Now()
			c.successCount++
			c.mu.Unlock()
			return nil
		}

		if attempt < c.retryConfig.MaxRetries-1 {
			c.logger.Warn("push attempt failed, retrying",
				zap.Int("attempt", attempt+1),
				zap.Duration("backoff", backoff),
				zap.Error(err),
			)

			select {
			case <-time.After(backoff):
				// Calculate next backoff
				backoff = time.Duration(float64(backoff) * c.retryConfig.BackoffMultiplier)
				if backoff > c.retryConfig.MaxBackoff {
					backoff = c.retryConfig.MaxBackoff
				}

			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	// ANCHOR: Increment failure count with mutex protection - Dec 26, 2025
	// Thread-safe update of failure counter
	c.mu.Lock()
	c.failureCount++
	c.mu.Unlock()
	return fmt.Errorf("push failed after %d attempts", c.retryConfig.MaxRetries)
}

// LastPushTime returns the time of last successful push
func (c *Client) LastPushTime() time.Time {
	// ANCHOR: Thread-safe read of lastPushTime with mutex - Dec 26, 2025
	// Protect time.Time field access with mutex instead of unsafe atomic operations
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastPushTime
}

// SuccessCount returns the total number of successful pushes
func (c *Client) SuccessCount() int64 {
	// ANCHOR: Thread-safe read of successCount with mutex - Dec 26, 2025
	// Protect counter access with mutex for consistency
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.successCount
}

// FailureCount returns the total number of failed pushes
func (c *Client) FailureCount() int64 {
	// ANCHOR: Thread-safe read of failureCount with mutex - Dec 26, 2025
	// Protect counter access with mutex for consistency
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.failureCount
}
