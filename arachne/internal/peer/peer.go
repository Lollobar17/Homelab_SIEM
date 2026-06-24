// internal/peer/peer.go
// ArachneC2 — P2P peer communication simulation
// Simulates libp2p DHT discovery, GossipSub PubSub, and NAT traversal patterns
package peer

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/Lollobar17/arachne-c2/internal/config"
)

// PeerEvent represents a peer-to-peer communication event.
type PeerEvent struct {
	Timestamp   string `json:"timestamp"`
	NodeID      string `json:"node_id"`
	EventType   string `json:"event_type"`
	PeerAddress string `json:"peer_address"`
	PeerID      string `json:"peer_id"`       // libp2p peer ID (12D3Koo... format)
	MessageType string `json:"message_type"` // "heartbeat"|"dht_discovery"|"gossipsub"|"nat_traversal"|"relay"
	Protocol    string `json:"protocol"`     // "/arachne/1.0.0"|"/ipfs/kad/1.0.0"
	Encrypted   bool   `json:"encrypted"`
	Signed      bool   `json:"signed"`
	Success     bool   `json:"success"`
	LatencyMs   int64  `json:"latency_ms"`
	NATType     string `json:"nat_type,omitempty"` // "cone"|"symmetric"|"none"
}

// PeerManager handles P2P communications between nodes.
type PeerManager struct {
	cfg      *config.Config
	peers    map[string]*Peer
	mu       sync.RWMutex
	client   *http.Client
	logger   EventLogger
	selfPeerID string
}

// Peer represents a known peer node.
type Peer struct {
	Address   string
	PeerID    string
	LastSeen  time.Time
	Reachable bool
	FailCount int
	NATType   string
}

// EventLogger logs peer events.
type EventLogger func(event PeerEvent)

// New creates a new PeerManager.
func New(cfg *config.Config, logger EventLogger) *PeerManager {
	pm := &PeerManager{
		cfg:        cfg,
		peers:      make(map[string]*Peer),
		client:     &http.Client{Timeout: 5 * time.Second},
		logger:     logger,
		selfPeerID: generateLibp2pPeerID(),
	}
	for _, addr := range cfg.PeerList {
		pm.peers[addr] = &Peer{
			Address: addr,
			PeerID:  generateLibp2pPeerID(),
			NATType: randomNATType(),
		}
	}
	return pm
}

// Start begins the peer communication loop.
func (pm *PeerManager) Start(ctx context.Context) {
	// DHT bootstrap ticker (slower)
	dhtTicker := time.NewTicker(60 * time.Second)
	// Heartbeat ticker (faster)
	heartbeatTicker := time.NewTicker(30 * time.Second)
	// GossipSub ticker
	gossipTicker := time.NewTicker(45 * time.Second)
	// Lateral movement ticker
	lateralTicker := time.NewTicker(pm.cfg.LateralInterval)

	defer dhtTicker.Stop()
	defer heartbeatTicker.Stop()
	defer gossipTicker.Stop()
	defer lateralTicker.Stop()

	// Initial DHT bootstrap
	pm.simulateDHTDiscovery()

	for {
		select {
		case <-ctx.Done():
			return
		case <-dhtTicker.C:
			pm.simulateDHTDiscovery()
		case <-heartbeatTicker.C:
			pm.heartbeatAll()
		case <-gossipTicker.C:
			pm.simulateGossipSub()
		case <-lateralTicker.C:
			if pm.cfg.LateralEnabled {
				pm.simulateLateralDiscovery()
			}
		}
	}
}

// simulateDHTDiscovery simulates libp2p Kademlia DHT peer discovery.
func (pm *PeerManager) simulateDHTDiscovery() {
	// Discover 2-5 new peers via DHT
	count := 2 + mrand.Intn(4)
	for i := 0; i < count; i++ {
		peerID := generateLibp2pPeerID()
		addr := fmt.Sprintf("/ip4/%d.%d.%d.%d/tcp/%d",
			mrand.Intn(223)+1,
			mrand.Intn(255),
			mrand.Intn(255),
			mrand.Intn(254)+1,
			4000+mrand.Intn(1000),
		)

		event := PeerEvent{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			NodeID:      pm.cfg.NodeID,
			EventType:   "dht_discovery",
			PeerAddress: addr,
			PeerID:      peerID,
			MessageType: "dht_discovery",
			Protocol:    "/ipfs/kad/1.0.0",
			Encrypted:   true,
			Signed:      true,
			Success:     mrand.Float32() > 0.3,
			LatencyMs:   int64(50 + mrand.Intn(400)),
			NATType:     randomNATType(),
		}

		// Attempt NAT traversal if behind NAT
		if event.NATType != "none" {
			pm.simulateNATTraversal(peerID, addr)
		}

		pm.logger(event)

		// Register discovered peer
		if event.Success {
			pm.mu.Lock()
			pm.peers[addr] = &Peer{
				Address:   addr,
				PeerID:    peerID,
				LastSeen:  time.Now(),
				Reachable: true,
				NATType:   event.NATType,
			}
			pm.mu.Unlock()
		}
	}
}

// simulateNATTraversal simulates libp2p hole punching.
func (pm *PeerManager) simulateNATTraversal(peerID, addr string) {
	event := PeerEvent{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		NodeID:      pm.cfg.NodeID,
		EventType:   "nat_traversal",
		PeerAddress: addr,
		PeerID:      peerID,
		MessageType: "nat_traversal",
		Protocol:    "/libp2p/circuit/relay/0.2.0/hop",
		Encrypted:   true,
		Signed:      true,
		Success:     mrand.Float32() > 0.4,
		LatencyMs:   int64(100 + mrand.Intn(800)),
		NATType:     randomNATType(),
	}
	pm.logger(event)
}

// simulateGossipSub simulates GossipSub PubSub message propagation.
func (pm *PeerManager) simulateGossipSub() {
	pm.mu.RLock()
	peerCount := len(pm.peers)
	pm.mu.RUnlock()

	if peerCount == 0 {
		return
	}

	topics := []string{
		"/arachne/beacon/1.0.0",
		"/arachne/tasks/1.0.0",
		"/arachne/results/1.0.0",
	}

	topic := topics[mrand.Intn(len(topics))]

	// Simulate publishing to GossipSub topic
	msgPayload := generateEncryptedPayload()

	pm.mu.RLock()
	peers := make([]*Peer, 0)
	for _, p := range pm.peers {
		if p.Reachable {
			peers = append(peers, p)
		}
	}
	pm.mu.RUnlock()

	// Publish to up to 6 mesh peers (GossipSub D parameter)
	meshSize := min(6, len(peers))
	for i := 0; i < meshSize; i++ {
		targetPeer := peers[mrand.Intn(len(peers))]
		event := PeerEvent{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			NodeID:      pm.cfg.NodeID,
			EventType:   "gossipsub_message",
			PeerAddress: targetPeer.Address,
			PeerID:      targetPeer.PeerID,
			MessageType: fmt.Sprintf("gossipsub[%s]", topic),
			Protocol:    "/meshsub/1.1.0",
			Encrypted:   true,
			Signed:      true,
			Success:     mrand.Float32() > 0.1,
			LatencyMs:   int64(10 + mrand.Intn(100)),
		}
		_ = msgPayload
		pm.logger(event)
	}
}

// heartbeatAll sends heartbeats to known peers.
func (pm *PeerManager) heartbeatAll() {
	pm.mu.RLock()
	peers := make([]*Peer, 0, len(pm.peers))
	for _, p := range pm.peers {
		peers = append(peers, p)
	}
	pm.mu.RUnlock()
	for _, peer := range peers {
		go pm.sendHeartbeat(peer)
	}
}

func (pm *PeerManager) sendHeartbeat(peer *Peer) {
	start := time.Now()
	event := PeerEvent{
		Timestamp:   start.UTC().Format(time.RFC3339),
		NodeID:      pm.cfg.NodeID,
		EventType:   "peer_communication",
		PeerAddress: peer.Address,
		PeerID:      peer.PeerID,
		MessageType: "heartbeat",
		Protocol:    "/arachne/1.0.0",
		Encrypted:   true,
		Signed:      true,
		Success:     false,
		NATType:     peer.NATType,
	}
	url := fmt.Sprintf("http://%s/peer/heartbeat", peer.Address)
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Header.Set("User-Agent", pm.cfg.UserAgent)
		req.Header.Set("X-Node-ID", pm.cfg.NodeID)
		req.Header.Set("X-Peer-ID", pm.selfPeerID)
		resp, err := pm.client.Do(req)
		event.LatencyMs = time.Since(start).Milliseconds()
		if err == nil {
			event.Success = resp.StatusCode == 200
			resp.Body.Close()
			pm.mu.Lock()
			peer.LastSeen = time.Now()
			peer.Reachable = event.Success
			pm.mu.Unlock()
		}
	}
	pm.logger(event)
}

// simulateLateralDiscovery simulates scanning internal network.
func (pm *PeerManager) simulateLateralDiscovery() {
	targets := []string{
		fmt.Sprintf("10.0.0.%d", 100+mrand.Intn(50)),
		fmt.Sprintf("192.168.1.%d", 10+mrand.Intn(240)),
		fmt.Sprintf("172.16.%d.%d", mrand.Intn(16), mrand.Intn(254)+1),
	}
	for _, target := range targets {
		event := PeerEvent{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			NodeID:      pm.cfg.NodeID,
			EventType:   "lateral_movement",
			PeerAddress: target,
			PeerID:      generateLibp2pPeerID(),
			MessageType: "discovery",
			Protocol:    "/arachne/1.0.0",
			Encrypted:   true,
			Signed:      false,
			Success:     mrand.Float32() > 0.7,
			LatencyMs:   int64(mrand.Intn(500)),
		}
		pm.logger(event)
	}
}

func (pm *PeerManager) GetPeerStatus() []byte {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	status := make([]map[string]interface{}, 0)
	for addr, peer := range pm.peers {
		status = append(status, map[string]interface{}{
			"address":    addr,
			"peer_id":    peer.PeerID,
			"reachable":  peer.Reachable,
			"last_seen":  peer.LastSeen.Format(time.RFC3339),
			"fail_count": peer.FailCount,
			"nat_type":   peer.NATType,
		})
	}
	data, _ := json.Marshal(status)
	return data
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// generateLibp2pPeerID generates a realistic libp2p peer ID (12D3Koo... format).
func generateLibp2pPeerID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return "12D3Koo" + base64.RawURLEncoding.EncodeToString(b)[:32]
}

// generateEncryptedPayload simulates NaCl box encrypted payload.
func generateEncryptedPayload() string {
	b := make([]byte, 64)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func randomNATType() string {
	types := []string{"cone", "symmetric", "none", "none"}
	return types[mrand.Intn(len(types))]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
