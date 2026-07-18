package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/lollobar17/my-purple-siem-lab/agent/pkg/models"
)

type Sender struct {
	Endpoint   string
	Token      string
	MaxRetries int
	client     *http.Client
}

func NewSender(endpoint, token string, maxRetries int) *Sender {
	return &Sender{
		Endpoint: endpoint, Token: token, MaxRetries: maxRetries,
		client: &http.Client{Timeout: 5 * time.Second},
	}
}

func (s *Sender) Send(event models.Telemetry) error {
	envelope := map[string]any{
		"source": "go-agent",
		"events": []map[string]any{event.ToIngressPayload()},
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("serializzazione JSON fallita: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= s.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * time.Second)
		}
		req, err := http.NewRequest(http.MethodPost, s.Endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("costruzione richiesta fallita: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Agent-Token", s.Token)

		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = err
			log.Printf("[sender] tentativo %d/%d fallito: %v", attempt+1, s.MaxRetries+1, err)
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				lastErr = nil
			} else if resp.StatusCode >= 500 {
				lastErr = fmt.Errorf("server error: %d", resp.StatusCode)
			} else {
				lastErr = fmt.Errorf("client error non recuperabile: %d", resp.StatusCode)
			}
		}()

		if lastErr == nil {
			return nil
		}
		if resp != nil && resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return lastErr
		}
	}
	return fmt.Errorf("invio fallito dopo %d tentativi: %w", s.MaxRetries+1, lastErr)
}
