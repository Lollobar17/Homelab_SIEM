// internal/beacon/beacon.go
// ArachneC2 — Beacon with randomized jitter and encrypted PubSub simulation
// Simulates libp2p GossipSub beacon topic with Ed25519 signed messages
package beacon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"time"

	"github.com/Lollobar17/arachne-c2/internal/config"
)

// BeaconEvent represents a single beacon transmission logged to file.
type BeaconEvent struct {
	Timestamp    string `json:"timestamp"`
	NodeID       string `json:"node_id"`
	PeerID       string `json:"peer_id"`       // libp2p peer ID
	EventType    string `json:"event_type"`
	TargetURL    string `json:"target_url"`
	MimicHost    string `json:"mimic_host"`
	UserAgent    string `json:"user_agent"`
	Protocol     string `json:"protocol"`      // "/arachne/beacon/1.0.0"
	Topic        string `json:"topic"`         // GossipSub topic
	Encrypted    bool   `json:"encrypted"`     // NaCl box encrypted
	Signed       bool   `json:"signed"`        // Ed25519 signed
	PayloadHash  string `json:"payload_hash"`  // simulated message hash
	StatusCode   int    `json:"status_code,omitempty"`
	JitterMs     int64  `json:"jitter_ms"`
	Success      bool   `json:"success"`
}

// Beaconer handles periodic C2 beacon transmissions.
type Beaconer struct {
	cfg      *config.Config
	client   *http.Client
	logger   EventLogger
	peerID   string
	privKey  string // simulated Ed25519 private key fingerprint
}

// EventLogger is a function that logs a beacon event.
type EventLogger func(event BeaconEvent)

// New creates a new Beaconer instance.
func New(cfg *config.Config, logger EventLogger) *Beaconer {
	privKeyBytes := make([]byte, 32)
	rand.Read(privKeyBytes)
	return &Beaconer{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
		peerID: generatePeerID(),
		privKey: hex.EncodeToString(privKeyBytes),
	}
}

// Start begins the beacon loop until context is cancelled.
func (b *Beaconer) Start(ctx context.Context) {
	// Initial beacon immediately
	b.sendBeacon()

	for {
		jitter := b.calculateJitter()
		sleepDuration := b.cfg.BeaconInterval + jitter
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleepDuration):
			b.sendBeacon()
		}
	}
}

// sendBeacon transmits one beacon (simulates GossipSub PubSub publish).
func (b *Beaconer) sendBeacon() {
	// Simulate NaCl box encrypted payload
	payloadBytes := make([]byte, 128)
	rand.Read(payloadBytes)
	payloadHash := hex.EncodeToString(payloadBytes[:32])

	// Simulate Ed25519 signature
	sigBytes := make([]byte, 64)
	rand.Read(sigBytes)

	event := BeaconEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		NodeID:      b.cfg.NodeID,
		PeerID:      b.peerID,
		EventType:   "c2_beacon",
		TargetURL:   b.cfg.BeaconURL,
		MimicHost:   b.cfg.MimicDomain,
		UserAgent:   b.cfg.UserAgent,
		Protocol:    "/arachne/beacon/1.0.0",
		Topic:       "/arachne/beacon/1.0.0",
		Encrypted:   true,
		Signed:      true,
		PayloadHash: payloadHash,
		JitterMs:    mrand.Int63n(int64(b.cfg.BeaconInterval.Milliseconds()) / 10),
		Success:     false,
	}

	// Build beacon payload (mimics libp2p message format)
	payload := map[string]interface{}{
		"from":      b.peerID,
		"topic":     "/arachne/beacon/1.0.0",
		"seqno":     fmt.Sprintf("%x", mrand.Int63()),
		"signature": base64.StdEncoding.EncodeToString(sigBytes),
		"key":       b.privKey[:16] + "...", // truncated for log safety
		"data":      base64.StdEncoding.EncodeToString(payloadBytes[:32]),
	}

	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", b.cfg.BeaconURL, bytes.NewReader(data))
	if err != nil {
		b.logger(event)
		return
	}

	// Evasion: mimic legitimate HTTP traffic
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", b.cfg.UserAgent)
	req.Header.Set("Host", b.cfg.MimicDomain)
	req.Header.Set("X-Request-ID", fmt.Sprintf("%x", mrand.Int63()))
	req.Header.Set("X-Forwarded-For", generateFakeIP())

	resp, err := b.client.Do(req)
	if err == nil {
		event.StatusCode = resp.StatusCode
		event.Success = resp.StatusCode == 200
		resp.Body.Close()
	}

	b.logger(event)
}

// calculateJitter returns a randomized duration offset (±jitter%).
func (b *Beaconer) calculateJitter() time.Duration {
	if b.cfg.BeaconJitter <= 0 {
		return 0
	}
	maxJitterMs := int64(float64(b.cfg.BeaconInterval.Milliseconds()) * b.cfg.BeaconJitter)
	if maxJitterMs <= 0 {
		return 0
	}
	jitterMs := mrand.Int63n(maxJitterMs*2) - maxJitterMs
	return time.Duration(jitterMs) * time.Millisecond
}

func generatePeerID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "12D3Koo" + base64.RawURLEncoding.EncodeToString(b)[:32]
}

func generateFakeIP() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		mrand.Intn(223)+1,
		mrand.Intn(255),
		mrand.Intn(255),
		mrand.Intn(254)+1,
	)
}
