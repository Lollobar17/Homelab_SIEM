package main

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/lollobar17/my-purple-siem-lab/agent/pkg/collector"
	"github.com/lollobar17/my-purple-siem-lab/agent/pkg/sender"
)

func main() {
	agentID := requireEnv("AGENT_ID")
	token := requireEnv("AGENT_TOKEN")
	endpoint := envOr("SIEM_INGEST_URL", "http://localhost:5000/api/v1/ingress")
	pollSeconds := envIntOr("AGENT_POLL_INTERVAL_SECONDS", 2)
	maxRetries := envIntOr("AGENT_MAX_RETRIES", 3)

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	log.Printf("[agent] avvio — agent_id=%s hostname=%s endpoint=%s poll=%ds",
		agentID, hostname, endpoint, pollSeconds)

	c := collector.NewCollector(agentID, hostname, time.Duration(pollSeconds)*time.Second)
	s := sender.NewSender(endpoint, token, maxRetries)

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	events := c.Start(stopCh)

	go func() {
		<-sigCh
		log.Println("[agent] segnale di shutdown ricevuto, arresto in corso...")
		close(stopCh)
	}()

	for event := range events {
		if err := s.Send(event); err != nil {
			log.Printf("[agent] invio evento fallito (pid=%d): %v", event.ProcessContext.PID, err)
			continue
		}
		log.Printf("[agent] evento inviato: pid=%d comm=%s action=%s",
			event.ProcessContext.PID, event.ProcessContext.ProcessName, event.EventData.Action)
	}
	log.Println("[agent] terminato")
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("[agent] variabile d'ambiente obbligatoria mancante: %s", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOr(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
