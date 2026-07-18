#!/usr/bin/env bash
# integrate_purple_team_lab.sh
#
# Da eseguire dalla ROOT del repo Homelab_SIEM (dove si trova app.py).
# Crea i nuovi moduli (agent/, purple-team/, siem/process_rules.py,
# tests/test_process_rules.py) e applica patch idempotenti a
# siem/detector.py, app.py e al workflow CI in .github/workflows/.
#
# Rieseguibile in sicurezza: ogni patch controlla prima se è già presente.

set -euo pipefail

if [ ! -f "app.py" ]; then
  echo "ERRORE: app.py non trovato nella directory corrente." >&2
  echo "Esegui questo script dalla root del repo Homelab_SIEM." >&2
  exit 1
fi

echo "==> Integrazione purple-team-lab in $(pwd)"

mkdir -p agent/cmd agent/pkg/collector agent/pkg/models agent/pkg/sender
mkdir -p purple-team/nim-loaders
mkdir -p tests

# ─────────────────────────────────────────────────────────────────────────
# 1. Go agent
# ─────────────────────────────────────────────────────────────────────────

echo "==> [1/7] Scrittura agent/go.mod"
cat > agent/go.mod << 'GOMOD'
module github.com/lollobar17/my-purple-siem-lab/agent

go 1.22
GOMOD

echo "==> [2/7] Scrittura agent/pkg/models/telemetry.go"
cat > agent/pkg/models/telemetry.go << 'GOFILE'
package models

import "fmt"

const SchemaVersion = "1.0"

type ProcessContext struct {
	PID               int    `json:"pid"`
	PPID              int    `json:"ppid"`
	ProcessName       string `json:"process_name"`
	ExecutablePath    string `json:"executable_path"`
	CommandLine       string `json:"command_line"`
	ParentProcessName string `json:"parent_process_name"`
	SHA256            string `json:"sha256,omitempty"`
}

type EventData struct {
	Action           string `json:"action"`
	ChildProcessName string `json:"child_process_name,omitempty"`
	ChildCommandLine string `json:"child_command_line,omitempty"`
	IntegrityLevel   string `json:"integrity_level,omitempty"`
}

type Telemetry struct {
	SchemaVersion  string         `json:"schema_version"`
	AgentID        string         `json:"agent_id"`
	Hostname       string         `json:"hostname"`
	Timestamp      string         `json:"timestamp"`
	EventType      string         `json:"event_type"`
	ProcessContext ProcessContext `json:"process_context"`
	EventData      EventData      `json:"event_data"`
}

// ToIngressPayload converte l'evento interno nello schema WIRE atteso da
// siem/ingress.py::normalize_event (category/event_type/message/fields).
func (t Telemetry) ToIngressPayload() map[string]any {
	pc := t.ProcessContext
	ed := t.EventData

	message := fmt.Sprintf(
		"process_creation pid=%d ppid=%d process=%s parent=%s action=%s",
		pc.PID, pc.PPID, pc.ProcessName, pc.ParentProcessName, ed.Action,
	)

	fields := map[string]any{
		"agent_id":            t.AgentID,
		"pid":                 pc.PID,
		"ppid":                pc.PPID,
		"process_name":        pc.ProcessName,
		"executable_path":     pc.ExecutablePath,
		"command_line":        pc.CommandLine,
		"parent_process_name": pc.ParentProcessName,
		"action":              ed.Action,
	}
	if pc.SHA256 != "" {
		fields["sha256"] = pc.SHA256
	}
	if ed.ChildProcessName != "" {
		fields["child_process_name"] = ed.ChildProcessName
	}
	if ed.ChildCommandLine != "" {
		fields["child_command_line"] = ed.ChildCommandLine
	}

	return map[string]any{
		"timestamp":  t.Timestamp,
		"source":     "go-agent",
		"category":   "process",
		"event_type": "process." + ed.Action,
		"message":    message,
		"fields":     fields,
	}
}
GOFILE

echo "==> [3/7] Scrittura agent/pkg/collector/process.go"
cat > agent/pkg/collector/process.go << 'GOFILE'
package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lollobar17/my-purple-siem-lab/agent/pkg/models"
)

type Collector struct {
	AgentID      string
	Hostname     string
	PollInterval time.Duration
	known        map[int]struct{}
}

func NewCollector(agentID, hostname string, pollInterval time.Duration) *Collector {
	return &Collector{
		AgentID: agentID, Hostname: hostname, PollInterval: pollInterval,
		known: make(map[int]struct{}),
	}
}

func (c *Collector) Start(stopCh <-chan struct{}) <-chan models.Telemetry {
	out := make(chan models.Telemetry, 64)
	c.snapshotBaseline()

	go func() {
		ticker := time.NewTicker(c.PollInterval)
		defer ticker.Stop()
		defer close(out)
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				c.pollOnce(out)
			}
		}
	}()
	return out
}

func (c *Collector) snapshotBaseline() {
	pids, err := listPIDs()
	if err != nil {
		return
	}
	for _, pid := range pids {
		c.known[pid] = struct{}{}
	}
}

func (c *Collector) pollOnce(out chan<- models.Telemetry) {
	pids, err := listPIDs()
	if err != nil {
		return
	}
	current := make(map[int]struct{}, len(pids))
	for _, pid := range pids {
		current[pid] = struct{}{}
		if _, seen := c.known[pid]; seen {
			continue
		}
		info, err := readProcessInfo(pid)
		if err != nil {
			continue
		}
		parentInfo, _ := readProcessInfo(info.ppid)

		event := models.Telemetry{
			SchemaVersion: models.SchemaVersion,
			AgentID:       c.AgentID,
			Hostname:      c.Hostname,
			Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
			EventType:     "process_creation",
			EventData: models.EventData{
				Action: "spawn", ChildProcessName: info.comm, ChildCommandLine: info.cmdline,
				IntegrityLevel: "medium",
			},
		}

		if parentInfo.pid == 0 {
			event.ProcessContext = models.ProcessContext{
				PID: info.pid, PPID: info.ppid, ProcessName: info.comm,
				ExecutablePath: info.exePath, CommandLine: info.cmdline,
				ParentProcessName: "unknown",
			}
			event.EventData.ChildProcessName = ""
			event.EventData.ChildCommandLine = ""
			event.EventData.Action = "exec"
		} else {
			event.ProcessContext = models.ProcessContext{
				PID: parentInfo.pid, PPID: info.ppid, ProcessName: parentInfo.comm,
				ExecutablePath: parentInfo.exePath, CommandLine: parentInfo.cmdline,
				ParentProcessName: parentInfo.comm,
			}
		}

		select {
		case out <- event:
		default:
		}
	}
	c.known = current
}

type procInfo struct {
	pid     int
	ppid    int
	comm    string
	exePath string
	cmdline string
}

func listPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("lettura /proc fallita: %w", err)
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func readProcessInfo(pid int) (procInfo, error) {
	if pid <= 0 {
		return procInfo{}, fmt.Errorf("pid non valido: %d", pid)
	}
	statPath := filepath.Join("/proc", strconv.Itoa(pid), "stat")
	statBytes, err := os.ReadFile(statPath)
	if err != nil {
		return procInfo{}, err
	}
	comm, ppid, err := parseStat(string(statBytes))
	if err != nil {
		return procInfo{}, err
	}
	exePath, _ := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	cmdline := strings.ReplaceAll(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00", " ")
	return procInfo{pid: pid, ppid: ppid, comm: comm, exePath: exePath, cmdline: cmdline}, nil
}

func parseStat(raw string) (comm string, ppid int, err error) {
	openIdx := strings.IndexByte(raw, '(')
	closeIdx := strings.LastIndexByte(raw, ')')
	if openIdx == -1 || closeIdx == -1 || closeIdx < openIdx {
		return "", 0, fmt.Errorf("formato /proc/[pid]/stat inatteso")
	}
	comm = raw[openIdx+1 : closeIdx]
	rest := strings.Fields(raw[closeIdx+1:])
	if len(rest) < 2 {
		return "", 0, fmt.Errorf("campi insufficienti in /proc/[pid]/stat")
	}
	ppid, err = strconv.Atoi(rest[1])
	if err != nil {
		return "", 0, fmt.Errorf("ppid non parsabile: %w", err)
	}
	return comm, ppid, nil
}
GOFILE

echo "==> [4/7] Scrittura agent/pkg/sender/http.go"
cat > agent/pkg/sender/http.go << 'GOFILE'
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
GOFILE

echo "==> [5/7] Scrittura agent/cmd/main.go"
cat > agent/cmd/main.go << 'GOFILE'
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
GOFILE

# ─────────────────────────────────────────────────────────────────────────
# 2. Nim loader (purple-team)
# ─────────────────────────────────────────────────────────────────────────

echo "==> [6/7] Scrittura purple-team/nim-loaders/loader.nim"
cat > purple-team/nim-loaders/loader.nim << 'NIMFILE'
## loader.nim — Purple team test runner.
## Contiene "uname -a" offuscato via XOR statico (chiave 0x5A).
## A runtime decodifica ed esegue il comando, per validare che il sistema
## di detection lo riconosca via analisi comportamentale (non statica).

import std/osproc

proc xorDecode(data: seq[uint8], key: uint8): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b xor key)

proc main() =
  let encodedCmd: seq[uint8] = @[
    0x2F'u8, 0x34'u8, 0x3B'u8, 0x37'u8, 0x3F'u8, 0x7A'u8, 0x77'u8, 0x3B'u8
  ]
  let key = 0x5A'u8
  let decoded = xorDecode(encodedCmd, key)

  echo "[loader] eseguo comando decodificato a runtime"
  let (output, exitCode) = execCmdEx(decoded)
  echo "[loader] exit code: ", exitCode
  echo "[loader] output:"
  echo output

when isMainModule:
  main()
NIMFILE

# ─────────────────────────────────────────────────────────────────────────
# 3. siem/process_rules.py + tests/test_process_rules.py
# ─────────────────────────────────────────────────────────────────────────

echo "==> [7/7] Scrittura siem/process_rules.py e tests/test_process_rules.py"
cat > siem/process_rules.py << 'PYFILE'
"""
process_rules.py — Detection rules for host process telemetry (Go agent).
"""

SUSPICIOUS_DISCOVERY_UTILS = {"uname", "id", "whoami", "hostname", "ifconfig", "ip", "w", "who"}
EXPECTED_PARENTS = {"bash", "sh", "zsh", "dash", "cmd.exe", "powershell.exe", "ansible", "ssh", "systemd"}


def _child_name(event: dict) -> str:
    return (event.get("fields", {}).get("child_process_name") or "").lower()


def _parent_name(event: dict) -> str:
    return (event.get("fields", {}).get("process_name") or "").lower()


def _is_process_spawn(event: dict) -> bool:
    return (
        event.get("category") == "process"
        and event.get("fields", {}).get("action") == "spawn"
        and bool(_child_name(event))
    )


PROCESS_RULES = [
    {
        "id": "PROC-001",
        "name": "Discovery Utility Spawned by Unwhitelisted Process",
        "description": (
            "Un processo non presente nella whitelist di parent attesi ha "
            "generato un'utility di discovery di sistema. Comportamento "
            "coerente con un binario che offusca staticamente il comando "
            "(T1027) per poi eseguire discovery post-exploitation (T1082)."
        ),
        "severity": "HIGH",
        "category": "process",
        "mitre": "T1082",
        "match": lambda e: (
            _is_process_spawn(e)
            and _child_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_name(e) not in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
    {
        "id": "PROC-002",
        "name": "Discovery Utility Spawned by Expected Parent",
        "description": (
            "Un'utility di discovery è stata lanciata da un parent atteso. "
            "Probabilmente benigno, segnalato a bassa severità per visibilità."
        ),
        "severity": "LOW",
        "category": "process",
        "mitre": "T1082",
        "match": lambda e: (
            _is_process_spawn(e)
            and _child_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_name(e) in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
]
PYFILE

cat > tests/test_process_rules.py << 'PYFILE'
"""tests/test_process_rules.py — Regression test per PROC-001/PROC-002."""

from siem.process_rules import PROCESS_RULES


def _fire(event: dict) -> list[str]:
    fired = []
    for rule in PROCESS_RULES:
        if rule["match"](event) and (rule["threshold"] is None or rule["threshold"](event)):
            fired.append(rule["id"])
    return fired


def _process_event(process_name: str, child_name: str) -> dict:
    return {
        "category": "process",
        "fields": {
            "action": "spawn",
            "process_name": process_name,
            "child_process_name": child_name,
            "child_command_line": f"{child_name} -a",
        },
    }


def test_unwhitelisted_parent_triggers_high_severity():
    event = _process_event(process_name="loader_test", child_name="uname")
    assert _fire(event) == ["PROC-001"]


def test_expected_parent_triggers_only_low_severity():
    event = _process_event(process_name="bash", child_name="uname")
    assert _fire(event) == ["PROC-002"]


def test_ansible_parent_does_not_trigger_high():
    event = _process_event(process_name="ansible", child_name="whoami")
    assert "PROC-001" not in _fire(event)


def test_non_process_category_is_ignored():
    event = {"category": "auth", "fields": {"message": "failed login"}}
    assert _fire(event) == []


def test_benign_child_process_does_not_trigger():
    event = _process_event(process_name="loader_test", child_name="ls")
    assert _fire(event) == []
PYFILE

# ─────────────────────────────────────────────────────────────────────────
# 4. Patch idempotente di siem/detector.py
# ─────────────────────────────────────────────────────────────────────────

echo "==> Patch siem/detector.py"
python3 - << 'PYEOF'
path = "siem/detector.py"
with open(path) as f:
    content = f.read()

changed = False

if "from siem.process_rules import PROCESS_RULES" not in content:
    anchor = "from siem.falco_rules import FALCO_RULES"
    if anchor not in content:
        print("  ATTENZIONE: ancora import FALCO_RULES non trovata, import non aggiunto — inseriscilo a mano")
    else:
        content = content.replace(
            anchor, anchor + "\nfrom siem.process_rules import PROCESS_RULES"
        )
        changed = True
        print("  -> import PROCESS_RULES aggiunto")
else:
    print("  -> import PROCESS_RULES già presente, skip")

if "RULES.extend(PROCESS_RULES)" not in content:
    anchor = "RULES.extend(FALCO_RULES)"
    if anchor not in content:
        print("  ATTENZIONE: ancora RULES.extend(FALCO_RULES) non trovata, riga non aggiunta — inseriscila a mano")
    else:
        content = content.replace(
            anchor, anchor + "\nRULES.extend(PROCESS_RULES)"
        )
        changed = True
        print("  -> RULES.extend(PROCESS_RULES) aggiunto")
else:
    print("  -> RULES.extend(PROCESS_RULES) già presente, skip")

if changed:
    with open(path, "w") as f:
        f.write(content)
PYEOF

# ─────────────────────────────────────────────────────────────────────────
# 5. Patch idempotente di app.py — autenticazione X-Agent-Token
# ─────────────────────────────────────────────────────────────────────────

echo "==> Patch app.py"
python3 - << 'PYEOF'
import re

path = "app.py"
with open(path) as f:
    content = f.read()

changed = False

if "import hmac" not in content:
    content = content.replace("import json\n", "import json\nimport hmac\n", 1)
    changed = True
    print("  -> import hmac aggiunto")
else:
    print("  -> import hmac già presente, skip")

# _check_agent_token usa os.getenv(): garantiamo che "import os" sia presente,
# indipendentemente da dove/come il file lo importa già.
if not re.search(r'^import os$', content, re.MULTILINE):
    if "import json\n" in content:
        content = content.replace("import json\n", "import json\nimport os\n", 1)
    else:
        content = "import os\n" + content
    changed = True
    print("  -> import os aggiunto")
else:
    print("  -> import os già presente, skip")

if "_check_agent_token" not in content:
    anchor = 'logger = logging.getLogger("siem.app")'
    if anchor not in content:
        print("  ATTENZIONE: ancora logger non trovata, blocco _check_agent_token non aggiunto — inseriscilo a mano")
    else:
        block = anchor + '''

_AGENT_TOKEN = os.getenv("SIEM_AGENT_TOKEN", "")
if not _AGENT_TOKEN:
    logger.warning(
        "[Security] SIEM_AGENT_TOKEN non impostato: /api/v1/ingress accetta "
        "richieste da chiunque, senza autenticazione."
    )


def _check_agent_token():
    """Ritorna una risposta 401 se il token e' mancante/errato, altrimenti None."""
    if not _AGENT_TOKEN:
        return None
    provided = request.headers.get("X-Agent-Token", "")
    if not hmac.compare_digest(provided, _AGENT_TOKEN):
        return jsonify({"error": "invalid or missing X-Agent-Token"}), 401
    return None'''
        content = content.replace(anchor, block, 1)
        changed = True
        print("  -> blocco _check_agent_token aggiunto")
else:
    print("  -> blocco _check_agent_token già presente, skip")

if "auth_error = _check_agent_token()" not in content:
    anchor = '    body = request.get_json(silent=True)\n    if body is None:'
    if anchor not in content:
        print("  ATTENZIONE: ancora corpo funzione ingress non trovata, chiamata auth non aggiunta — inseriscila a mano")
    else:
        replacement = (
            "    auth_error = _check_agent_token()\n"
            "    if auth_error:\n"
            "        return auth_error\n\n"
            + anchor
        )
        content = content.replace(anchor, replacement, 1)
        changed = True
        print("  -> chiamata _check_agent_token() aggiunta in api_v1_ingress")
else:
    print("  -> chiamata _check_agent_token() già presente, skip")

if changed:
    with open(path, "w") as f:
        f.write(content)
PYEOF

# ─────────────────────────────────────────────────────────────────────────
# 6. Patch idempotente del workflow CI — nuovo job purple-team-lab
# ─────────────────────────────────────────────────────────────────────────

WORKFLOW_FILE=""
for candidate in .github/workflows/*.yml .github/workflows/*.yaml; do
  if [ -f "$candidate" ] && grep -q "build-push:" "$candidate" 2>/dev/null; then
    WORKFLOW_FILE="$candidate"
    break
  fi
done

if [ -z "$WORKFLOW_FILE" ]; then
  echo "==> Nessun workflow con job 'build-push:' trovato in .github/workflows/, salto la patch CI"
  echo "    (aggiungi manualmente il job da ci_purple_team_job.yml)"
else
  echo "==> Patch $WORKFLOW_FILE — aggiunta job purple-team-lab"
  python3 - "$WORKFLOW_FILE" << 'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

if "purple-team-lab:" in content:
    print("  -> job purple-team-lab già presente, skip")
else:
    job_block = '''  purple-team-lab:
    name: "Purple Team Lab — Build & Behavioral Test"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout codice
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Installa Nim
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y nim

      - name: Build agente Go
        run: |
          cd agent
          go build ./...

      - name: Compila runner Nim (loader offuscato XOR)
        run: |
          cd purple-team/nim-loaders
          nim c -d:release --hints:off -o:loader_test loader.nim

      - name: "Verifica analisi statica: 'uname' non deve essere in chiaro"
        run: |
          cd purple-team/nim-loaders
          if strings loader_test | grep -qi "uname"; then
            echo "::error::Stringa 'uname' trovata in chiaro nel binario"
            exit 1
          fi

      - name: "Verifica analisi dinamica: il comando deve eseguire correttamente"
        run: |
          cd purple-team/nim-loaders
          OUTPUT=$(./loader_test)
          echo "$OUTPUT"
          if ! echo "$OUTPUT" | grep -qi "linux"; then
            echo "::error::Output inatteso"
            exit 1
          fi

'''
    anchor = "  build-push:\n"
    if anchor not in content:
        print("  ATTENZIONE: ancora 'build-push:' non trovata, job non inserito — incollalo a mano da ci_purple_team_job.yml")
    else:
        content = content.replace(anchor, job_block + anchor, 1)
        with open(path, "w") as f:
            f.write(content)
        print("  -> job purple-team-lab inserito prima di build-push")
PYEOF

  echo "==> Patch $WORKFLOW_FILE — aggiunta job release-agent-binaries"
  python3 - "$WORKFLOW_FILE" << 'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

if "release-agent-binaries:" in content:
    print("  -> job release-agent-binaries già presente, skip")
else:
    job_block = '''  release-agent-binaries:
    name: "Release — Cross-compile Go Agent"
    runs-on: ubuntu-latest
    needs: ci
    if: startsWith(github.ref, 'refs/tags/v')
    permissions:
      contents: write

    steps:
      - name: Checkout codice
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Cross-compila per linux/amd64 e linux/arm64
        run: |
          cd agent
          mkdir -p ../dist
          for arch in amd64 arm64; do
            echo "=== build linux/$arch ==="
            CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build \\
              -ldflags="-s -w -X main.version=${GITHUB_REF_NAME}" \\
              -o ../dist/purple-agent-linux-$arch ./cmd
          done

      - name: Verifica che i binari siano statici
        run: |
          cd dist
          for f in purple-agent-linux-*; do
            file "$f"
            file "$f" | grep -q "statically linked" || { echo "::error::$f non e' statico"; exit 1; }
          done

      - name: Genera checksum SHA256
        run: |
          cd dist
          sha256sum purple-agent-linux-* > checksums.txt

      - name: Pubblica su GitHub Release
        uses: softprops/action-gh-release@v3
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          files: |
            dist/purple-agent-linux-amd64
            dist/purple-agent-linux-arm64
            dist/checksums.txt
          generate_release_notes: true

'''
    anchor = "  build-push:\n"
    if anchor not in content:
        print("  ATTENZIONE: ancora 'build-push:' non trovata, job non inserito — incollalo a mano da ci_release_agent_job.yml")
    else:
        content = content.replace(anchor, job_block + anchor, 1)
        with open(path, "w") as f:
            f.write(content)
        print("  -> job release-agent-binaries inserito prima di build-push")
PYEOF
fi

# ─────────────────────────────────────────────────────────────────────────
# 7. Dependabot — aggiornamento automatico delle GitHub Action (idempotente)
# ─────────────────────────────────────────────────────────────────────────

mkdir -p .github/workflows

if [ -f ".github/dependabot.yml" ]; then
  echo "==> .github/dependabot.yml già presente, non lo sovrascrivo"
else
  echo "==> Scrittura .github/dependabot.yml (github-actions, pip, docker, helm, gomod)"
  cat > .github/dependabot.yml << 'DEPEOF'
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels: ["dependencies", "ci"]
    commit-message:
      prefix: "ci"
      include: "scope"
    groups:
      github-actions-minor-patch:
        patterns: ["*"]
        update-types: ["minor", "patch"]

  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    labels: ["dependencies", "python"]
    groups:
      python-minor-patch:
        patterns: ["*"]
        update-types: ["minor", "patch"]

  - package-ecosystem: "docker"
    directory: "/k8s"
    schedule:
      interval: "weekly"
      day: "monday"
    labels: ["dependencies", "docker"]

  - package-ecosystem: "docker"
    directory: "/scripts"
    schedule:
      interval: "weekly"
      day: "monday"
    labels: ["dependencies", "docker"]

  - package-ecosystem: "docker"
    directory: "/k8s/homelab-siem-chart"
    schedule:
      interval: "weekly"
      day: "monday"
    labels: ["dependencies", "helm"]

  - package-ecosystem: "gomod"
    directory: "/agent"
    schedule:
      interval: "weekly"
      day: "monday"
    labels: ["dependencies", "go"]
DEPEOF
fi

if [ -f ".github/workflows/dependabot-auto-merge.yml" ]; then
  echo "==> .github/workflows/dependabot-auto-merge.yml già presente, non lo sovrascrivo"
else
  echo "==> Scrittura .github/workflows/dependabot-auto-merge.yml"
  cat > .github/workflows/dependabot-auto-merge.yml << 'AMEOF'
name: Dependabot Auto-Merge

on: pull_request

permissions:
  contents: write
  pull-requests: write

jobs:
  dependabot-auto-merge:
    runs-on: ubuntu-latest
    if: github.event.pull_request.user.login == 'dependabot[bot]'
    steps:
      - name: Fetch Dependabot metadata
        id: metadata
        uses: dependabot/fetch-metadata@v3
        with:
          github-token: "${{ secrets.GITHUB_TOKEN }}"

      - name: Auto-merge solo per minor/patch
        if: |
          steps.metadata.outputs.update-type == 'version-update:semver-patch' ||
          steps.metadata.outputs.update-type == 'version-update:semver-minor'
        run: gh pr merge --auto --squash "$PR_URL"
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}

      - name: Commento su PR major — richiede revisione manuale
        if: steps.metadata.outputs.update-type == 'version-update:semver-major'
        run: |
          gh pr comment "$PR_URL" --body \
            "⚠️ Bump MAJOR rilevato ($DEP_NAMES). Non auto-mergiata: verifica breaking change prima di approvare manualmente."
        env:
          PR_URL: ${{ github.event.pull_request.html_url }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          DEP_NAMES: ${{ steps.metadata.outputs.dependency-names }}
AMEOF
fi

if [ -f ".github/workflows/canary.yml" ]; then
  echo "==> .github/workflows/canary.yml già presente, non lo sovrascrivo"
else
  echo "==> Scrittura .github/workflows/canary.yml (rebuild schedulato + issue automatica)"
  cat > .github/workflows/canary.yml << 'CANEOF'
name: Canary — Rebuild & Smoke Test

on:
  schedule:
    - cron: "0 4 * * 1"
  workflow_dispatch: {}

permissions:
  contents: read
  issues: write

jobs:
  canary:
    name: "Canary — rebuild con immagini fresche + smoke test"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout codice
        uses: actions/checkout@v4

      - name: Build immagine SIEM (forzando pull delle basi più recenti)
        id: build
        continue-on-error: true
        run: docker build --pull -t canary-siem:latest -f k8s/Dockerfile .

      - name: Avvia container e attendi readiness
        id: run
        if: steps.build.outcome == 'success'
        continue-on-error: true
        run: |
          docker run -d --name canary-siem -p 5000:5000 canary-siem:latest
          for i in $(seq 1 15); do
            if curl -sf http://localhost:5000/api/health > /dev/null; then
              echo "healthy=true" >> "$GITHUB_OUTPUT"
              exit 0
            fi
            sleep 2
          done
          echo "healthy=false" >> "$GITHUB_OUTPUT"
          docker logs canary-siem || true
          exit 1

      - name: Esegui smoke test applicativo (pytest, se presente)
        id: smoke
        if: steps.run.outcome == 'success'
        continue-on-error: true
        run: |
          if [ -d "tests" ]; then
            pip install --break-system-packages -q -r requirements.txt pytest
            pytest tests/ -v --tb=short
          else
            echo "nessuna cartella tests/, salto"
          fi

      - name: Determina esito complessivo
        id: outcome
        run: |
          if [ "${{ steps.build.outcome }}" = "success" ] && \
             [ "${{ steps.run.outcome }}" = "success" ] && \
             [ "${{ steps.smoke.outcome }}" != "failure" ]; then
            echo "failed=false" >> "$GITHUB_OUTPUT"
          else
            echo "failed=true" >> "$GITHUB_OUTPUT"
          fi

      - name: Apri o aggiorna Issue in caso di fallimento
        if: steps.outcome.outputs.failed == 'true'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          TITLE="🐤 Canary fallito — build/smoke test rotto ($(date -u +%Y-%m-%d))"
          BODY="Il canary schedulato ha rilevato un problema.

          - Build immagine: \`${{ steps.build.outcome }}\`
          - Avvio + health check: \`${{ steps.run.outcome }}\`
          - Smoke test pytest: \`${{ steps.smoke.outcome }}\`

          Possibile causa: un'immagine base upstream ha ricevuto un aggiornamento
          silenzioso non intercettato da Dependabot.

          Log: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"

          EXISTING=$(gh issue list --search "in:title \"Canary fallito\" is:open" --json number --jq '.[0].number // empty')

          if [ -n "$EXISTING" ]; then
            gh issue comment "$EXISTING" --body "Il canary è ancora rosso. $BODY"
          else
            gh issue create --title "$TITLE" --body "$BODY" --label "canary,bug"
          fi

      - name: Cleanup container
        if: always()
        run: docker rm -f canary-siem 2>/dev/null || true
CANEOF
fi


# ─────────────────────────────────────────────────────────────────────────
# 8. Progetto Nim strutturato — purple-team/nim/
# ─────────────────────────────────────────────────────────────────────────
#
# Evoluzione del laboratorio Nim verso una struttura modulare (nimble.nimble
# + src/ + tests/), separata dal semplice purple-team/nim-loaders/loader.nim
# esistente (che resta invariato, con il proprio job CI purple-team-lab).
# Ogni file qui sotto viene riscritto per intero ad ogni esecuzione (stesso
# "Modello A" già usato per agent/*.go e siem/process_rules.py): sono file
# generati e di proprietà dello script, non pensati per modifiche manuali.

echo "==> [8/9] Scrittura progetto Nim in purple-team/nim/"
mkdir -p purple-team/nim/src purple-team/nim/tests/fixtures

echo "==> [1/22] Scrittura purple-team/nim/nimble.nimble"
cat > purple-team/nim/nimble.nimble << 'NIMBLETOML'
version       = "0.1.0"
author        = "Lorenzo"
description   = "Laboratorio didattico Nim per il Purple Team/SIEM lab (Homelab_SIEM)"
license       = "MIT"
srcDir        = "src"
bin           = @["main"]

requires "nim >= 1.6.0"
# Nessuna dipendenza esterna: tutto il laboratorio usa solo la libreria
# standard di Nim (std/json, std/httpclient, std/unittest, ...).

task test, "Compila ed esegue l'intera suite di test del laboratorio":
  # I binari fixture per artifact_analysis NON sono committati in git
  # (sono artefatti compilati, platform-specific): vengono ricompilati qui
  # ad ogni esecuzione, in modo che il modulo possa analizzarli davvero.
  exec "nim c -d:release --hints:off tests/fixtures/plaintext_sample.nim"
  exec "nim c -d:release --hints:off tests/fixtures/obfuscated_sample.nim"

  exec "nim c -r --hints:off tests/test_models.nim"
  exec "nim c -r --hints:off tests/test_telemetry.nim"
  exec "nim c -r --hints:off tests/test_sender.nim"
  exec "nim c -r --hints:off tests/test_scenarios.nim"
  exec "nim c -r --hints:off tests/test_transform_lab.nim"
  exec "nim c -r --hints:off tests/test_artifact_analysis.nim"
  exec "nim c -r --hints:off tests/test_system_event_lab.nim"
  exec "nim c -r --hints:off tests/test_behavior_lab.nim"
  exec "nim c -r --hints:off tests/test_correlation_lab.nim"
  exec "nim c -r --hints:off tests/test_signal_coverage.nim"
NIMBLETOML

echo "==> [2/22] Scrittura purple-team/nim/src/models.nim"
cat > purple-team/nim/src/models.nim << 'NIMMODELS'
## models.nim — Tipi dati di telemetria per il laboratorio Purple Team/SIEM.
##
## Responsabilità unica di questo modulo: definire COSA sono i dati.
## Non serializza, non invia, non genera scenari: quello è compito di
## telemetry.nim, sender.nim e scenarios.nim.
##
## Equivalente concettuale di agent/pkg/models/telemetry.go (Go), riscritto
## con i costrutti idiomatici di Nim.

const SchemaVersion* = "1.0"
  ## `const` = valore noto e fissato in fase di compilazione (non a runtime).
  ## Diverso da `let` (valore fissato a runtime, una volta) e da `var`
  ## (modificabile). Qui SchemaVersion non cambierà mai durante l'esecuzione,
  ## quindi `const` è la scelta più corretta e più efficiente delle tre.

type
  EventCategory* = enum
    ## Un `enum` è un insieme CHIUSO di valori. Il compilatore impedisce di
    ## passare una categoria che non esiste — a differenza di una stringa
    ## libera, che potrebbe contenere un refuso mai controllato.
    ##
    ## La sintassi `ecProcess = "process"` assegna a ogni membro anche una
    ## rappresentazione testuale: `$ecProcess` restituirà "process", pronta
    ## per finire in un campo JSON senza bisogno di una tabella di mapping.
    ecProcess = "process"
    ecTransform = "transform"
    ecArtifact = "artifact"
    ecLifecycle = "lifecycle"
    ecSignal = "signal"
    ecBehavior = "behavior"
    ecCorrelation = "correlation"

  ProcessContext* = object
    ## `object` = "struct". Ogni campo ha un tipo esplicito, nessuna inferenza.
    pid*: int
    ppid*: int
    processName*: string
    executablePath*: string
    commandLine*: string
    parentProcessName*: string
    sha256*: string
      ## Stringa vuota "" = campo assente. È l'equivalente Nim del tag Go
      ## `json:"sha256,omitempty"`: la decisione se includerlo nel JSON finale
      ## non si prende qui (models.nim non sa nulla di JSON), ma in
      ## telemetry.nim, che leggerà `sha256.len > 0`.

  EventData* = object
    action*: string
    childProcessName*: string
    childCommandLine*: string
    integrityLevel*: string

  Telemetry* = object
    ## Il modello "envelope" per eventi di tipo processo — equivalente 1:1
    ## della struct Go Telemetry. Gli altri laboratori (transform, artifact,
    ## lifecycle, ...) NON useranno ProcessContext/EventData: avranno il
    ## proprio modello dedicato definito nel loro stesso file, per rispettare
    ## il principio "una responsabilità per modulo". Questo tipo resta quindi
    ## specifico per la telemetria di processo, in parità con il Go agent.
    schemaVersion*: string
    agentId*: string
    hostname*: string
    timestamp*: string
    eventType*: string
    source*: string
      ## "nim-agent", per distinguere lato SIEM gli eventi generati da questo
      ## laboratorio da quelli del Go agent ("go-agent"), pur condividendo
      ## lo stesso schema di detection.
    category*: EventCategory
    processContext*: ProcessContext
    eventData*: EventData

  Result*[T] = object
    ## Generic: lo stesso `Result` funziona per qualsiasi T (Result[int],
    ## Result[Telemetry], Result[string], ...) — il tipo concreto si decide
    ## alla chiamata, non qui.
    ##
    ## `case isOk*: bool` rende questo un "object variante": a seconda del
    ## valore di isOk, l'oggetto ha in memoria SOLO i campi del ramo attivo
    ## (true → value, false → error). Provare a leggere `.error` quando
    ## isOk == true è un errore rilevato a runtime, non un campo "vuoto".
    ## È il modo Nim di dire "questa operazione può fallire, e il chiamante
    ## è OBBLIGATO a gestire entrambi i casi" — niente eccezioni silenziose.
    case isOk*: bool
    of true:
      value*: T
    of false:
      error*: string

proc ok*[T](value: T): Result[T] =
  ## Costruttore per il caso di successo. Il parametro `[T]` è dedotto dal
  ## tipo di `value` passato: `ok(42)` produce un Result[int] senza doverlo
  ## scrivere esplicitamente.
  Result[T](isOk: true, value: value)

proc err*[T](error: string): Result[T] =
  ## Qui invece T NON può essere dedotto (l'unico argomento è una stringa),
  ## quindi va specificato esplicitamente alla chiamata: err[Telemetry]("...").
  Result[T](isOk: false, error: error)

proc newProcessContext*(pid, ppid: int, processName, executablePath,
                         commandLine, parentProcessName: string,
                         sha256: string = ""): ProcessContext =
  ## `sha256: string = ""` è un parametro con valore di default: chi chiama
  ## questa proc può ometterlo, ed è il caso comune (la maggior parte degli
  ## eventi non porta un hash).
  ProcessContext(
    pid: pid, ppid: ppid, processName: processName,
    executablePath: executablePath, commandLine: commandLine,
    parentProcessName: parentProcessName, sha256: sha256
  )

proc newTelemetry*(agentId, hostname, timestamp, eventType: string,
                    category: EventCategory,
                    processContext: ProcessContext,
                    eventData: EventData): Telemetry =
  ## Costruttore esplicito. In Nim non esiste un "new Telemetry(...)"
  ## implicito come in linguaggi OOP classici: si scrive una proc che
  ## restituisce l'object già popolato. Il prefisso `newX` è la convenzione
  ## idiomatica Nim (si vedano newSeq, newString nella libreria standard).
  result = Telemetry(
    schemaVersion: SchemaVersion,
    agentId: agentId,
    hostname: hostname,
    timestamp: timestamp,
    eventType: eventType,
    source: "nim-agent",
    category: category,
    processContext: processContext,
    eventData: eventData
  )
  ## Nota su `result`: in Nim ogni proc con un tipo di ritorno ha una
  ## variabile implicita chiamata `result`, già inizializzata al valore di
  ## default del tipo (per un object, tutti i campi a zero/""). Assegnarla
  ## e non scrivere `return` esplicito è lo stile idiomatico più comune.

proc validate*(t: Telemetry): Result[Telemetry] =
  ## Primo vero utilizzo di Result: alcuni campi non hanno senso vuoti
  ## (un agentId vuoto è quasi certamente un bug a monte). Restituendo
  ## Result invece di sollevare un'eccezione, chi chiama è costretto dal
  ## compilatore a controllare `isOk` prima di usare `.value`.
  if t.agentId.len == 0:
    return err[Telemetry]("agentId non può essere vuoto")
  if t.hostname.len == 0:
    return err[Telemetry]("hostname non può essere vuoto")
  if t.processContext.pid < 0:
    return err[Telemetry]("pid non può essere negativo: " & $t.processContext.pid)
  ok(t)
NIMMODELS

echo "==> [3/22] Scrittura purple-team/nim/src/telemetry.nim"
cat > purple-team/nim/src/telemetry.nim << 'NIMTELEMETRY'
## telemetry.nim — Serializzazione: Nim model → JSON.
##
## Responsabilità unica: trasformare i tipi definiti in models.nim (o le
## "fields" grezze degli altri laboratori) nello schema WIRE che il SIEM
## si aspetta in ingresso:
##
##   {timestamp, source, category, event_type, message, fields{...}}
##
## Questo modulo NON apre connessioni HTTP (è compito di sender.nim) e NON
## decide COSA generare (è compito di scenarios.nim e dei laboratori
## didattici). Fa solo da "traduttore" tra modello e JSON.

import std/json
import ./models

proc toIngressPayload*(t: Telemetry): JsonNode =
  ## Equivalente della ToIngressPayload() del Go agent, per la telemetria
  ## di processo. Stessa logica: costruisce un messaggio leggibile, poi un
  ## oggetto "fields" con i campi sempre presenti, aggiungendo quelli
  ## opzionali solo se non vuoti (== "omitempty" in Go).
  let pc = t.processContext
  let ed = t.eventData

  let message = "process_creation pid=" & $pc.pid &
                " ppid=" & $pc.ppid &
                " process=" & pc.processName &
                " parent=" & pc.parentProcessName &
                " action=" & ed.action

  var fields = %*{
    "agent_id": t.agentId,
    "pid": pc.pid,
    "ppid": pc.ppid,
    "process_name": pc.processName,
    "executable_path": pc.executablePath,
    "command_line": pc.commandLine,
    "parent_process_name": pc.parentProcessName,
    "action": ed.action
  }
  ## `fields` è `var`, non `let`: a differenza dell'oggetto Telemetry (che
  ## costruiamo già completo), qui aggiungiamo chiavi condizionalmente dopo
  ## la creazione — serve poterlo modificare.

  if pc.sha256.len > 0:
    fields["sha256"] = %pc.sha256
  if ed.childProcessName.len > 0:
    fields["child_process_name"] = %ed.childProcessName
  if ed.childCommandLine.len > 0:
    fields["child_command_line"] = %ed.childCommandLine

  result = %*{
    "timestamp": t.timestamp,
    "source": t.source,
    "category": $t.category,
    "event_type": t.eventType,
    "message": message,
    "fields": fields
  }

proc buildGenericEvent*(category: EventCategory, eventType, message: string,
                         fields: JsonNode, timestamp: string,
                         source: string = "nim-agent"): JsonNode =
  ## I laboratori didattici che verranno dopo (transform_lab, artifact_analysis,
  ## system_event_lab, behavior_lab, correlation_lab) NON parlano di processi:
  ## non hanno un ProcessContext/EventData sensato. Userranno questa proc più
  ## generica, passando direttamente le proprie "fields" già costruite.
  ##
  ## Questo evita di duplicare qui la logica di assemblaggio dell'envelope
  ## per ogni singolo laboratorio: la responsabilità di "che forma ha
  ## l'envelope finale" resta unica, in questo modulo.
  result = %*{
    "timestamp": timestamp,
    "source": source,
    "category": $category,
    "event_type": eventType,
    "message": message,
    "fields": fields
  }

proc serialize*(payload: JsonNode): string =
  ## Converte il JsonNode in stringa compatta, pronta per il body di una
  ## richiesta HTTP POST (compito di sender.nim, non di questo modulo).
  $payload

proc parseIngressPayload*(raw: string): Result[JsonNode] =
  ## Percorso inverso: da stringa a JsonNode, con gestione esplicita
  ## dell'errore invece di lasciar propagare l'eccezione che std/json
  ## solleva su JSON malformato (JsonParsingError). Usato dai test e da
  ## eventuali laboratori che verificano un round-trip serializza→deserializza.
  try:
    ok(parseJson(raw))
  except JsonParsingError as e:
    err[JsonNode]("JSON non valido: " & e.msg)
NIMTELEMETRY

echo "==> [4/22] Scrittura purple-team/nim/src/sender.nim"
cat > purple-team/nim/src/sender.nim << 'NIMSENDER'
## sender.nim — Invio HTTP del payload di telemetria verso il SIEM ingress.
##
## Responsabilità unica: prendere una stringa JSON già pronta (prodotta da
## telemetry.nim) e consegnarla via HTTP POST, con retry/backoff in caso di
## errore server, senza ritentare su errori client (4xx). Non costruisce
## il payload, non decide cosa inviare.

import std/httpclient
import std/os
import ./models

type
  HttpResult* = object
    code*: int
    body*: string

  Transport* = proc(url, body, token: string): HttpResult
    ## Una proc-come-valore: chiunque implementi questa firma può fare da
    ## "trasporto". In produzione è httpTransport (sotto); nei test è una
    ## funzione finta che restituisce risultati programmati, senza rete.

  SenderConfig* = object
    endpoint*: string
    agentToken*: string
    maxRetries*: int
    retryBaseDelayMs*: int
      ## In produzione: 1000ms, raddoppiati ad ogni tentativo (backoff
      ## esponenziale). Nei test: valori piccoli o sleepFn finta, per non
      ## far durare la suite di test decine di secondi.

proc newSenderConfig*(endpoint: string, agentToken: string = "",
                       maxRetries: int = 3,
                       retryBaseDelayMs: int = 1000): SenderConfig =
  SenderConfig(endpoint: endpoint, agentToken: agentToken,
               maxRetries: maxRetries, retryBaseDelayMs: retryBaseDelayMs)

proc httpTransport*(url, body, token: string): HttpResult =
  ## Trasporto reale: apre una connessione HTTP effettiva verso il SIEM.
  let client = newHttpClient(timeout = 5000)
  ## `defer` esegue l'istruzione alla USCITA dal blocco proc, qualunque sia
  ## il percorso (successo, errore, return anticipato) — garantisce che la
  ## connessione venga sempre chiusa, come `defer resp.Body.Close()` in Go.
  defer: client.close()
  client.headers = newHttpHeaders({
    "Content-Type": "application/json",
    "X-Agent-Token": token
  })
  try:
    let response = client.post(url, body = body)
    result = HttpResult(code: response.code.int, body: response.body)
  except CatchableError as e:
    ## code = 0 segnala "non ho nemmeno ricevuto una risposta" (errore di
    ## rete/connessione), distinto da un vero status code HTTP.
    result = HttpResult(code: 0, body: "transport error: " & e.msg)

proc send*(config: SenderConfig, body: string,
           transport: Transport = httpTransport,
           sleepFn: proc(ms: int) = os.sleep): Result[int] =
  ## Ritorna Result[int]: in caso di successo, il codice HTTP 2xx ricevuto;
  ## in caso di fallimento, un errore testuale dopo aver esaurito i tentativi.
  ##
  ## Logica di retry, identica a quella del Go agent:
  ##   - 2xx           -> successo immediato
  ##   - 4xx           -> errore non recuperabile, NESSUN retry
  ##   - 5xx / code==0 -> errore recuperabile, retry con backoff esponenziale
  var lastError = ""
  for attempt in 0 .. config.maxRetries:
    if attempt > 0:
      sleepFn(config.retryBaseDelayMs * (1 shl (attempt - 1)))

    let res = transport(config.endpoint, body, config.agentToken)

    if res.code >= 200 and res.code < 300:
      return ok(res.code)
    elif res.code >= 400 and res.code < 500:
      return err[int]("errore client non recuperabile: " & $res.code)
    else:
      lastError = "errore trasporto/server: code=" & $res.code & " body=" & res.body

  err[int]("invio fallito dopo " & $(config.maxRetries + 1) &
           " tentativi: " & lastError)
NIMSENDER

echo "==> [5/22] Scrittura purple-team/nim/src/scenarios.nim"
cat > purple-team/nim/src/scenarios.nim << 'NIMSCENARIOS'
## scenarios.nim — Catalogo dichiarativo di scenari sintetici.
##
## Responsabilità unica: descrivere COSA rappresenta uno scenario (id, nome,
## descrizione, categoria, parametri), NON come costruirne l'evento o come
## inviarlo — quello è compito dei singoli laboratori (transform_lab.nim,
## system_event_lab.nim, ecc.) e di sender.nim.
##
## Tenere gli scenari come puri dati permette di elencarli, filtrarli o
## esportarli (es. per signal_coverage.nim) senza eseguire nulla.

import ./models

type
  ScenarioParam* = object
    key*: string
    value*: string
      ## Rappresentazione sempre come stringa: è il modo più semplice per
      ## restare "dato puro" senza dover creare una variante per ogni tipo
      ## possibile di parametro. Ogni laboratorio converte al tipo che gli
      ## serve (es. parseInt su "50" per ottenere un int).

  Scenario* = object
    id*: string
    name*: string
    description*: string
    category*: EventCategory
    params*: seq[ScenarioParam]
      ## `seq` = dimensione dinamica: scenari diversi hanno un numero
      ## diverso di parametri, e non lo sappiamo a priori in fase di
      ## scrittura del tipo.

proc param*(key, value: string): ScenarioParam =
  ScenarioParam(key: key, value: value)

proc newScenario*(id, name, description: string, category: EventCategory,
                   params: seq[ScenarioParam] = @[]): Scenario =
  ## `@[]` è la sintassi letterale per un seq vuoto (equivalente di `[]byte{}`
  ## o di una slice vuota in Go). Il default vuoto copre gli scenari che non
  ## hanno bisogno di parametri.
  Scenario(id: id, name: name, description: description,
           category: category, params: params)

proc getParam*(s: Scenario, key: string): Result[string] =
  ## Cerca un parametro per chiave. Restituisce Result invece di una
  ## stringa vuota in caso di assenza: una stringa vuota potrebbe essere un
  ## valore legittimo, quindi "non trovato" dev'essere un caso distinto e
  ## gestito esplicitamente da chi chiama.
  for p in s.params:
    if p.key == key:
      return ok(p.value)
  err[string]("parametro '" & key & "' non trovato nello scenario '" & s.id & "'")

const BuiltinScenarios*: array[4, Scenario] = [
  ## `array[4, Scenario]` = dimensione FISSA, nota qui in fase di scrittura
  ## del codice. Se in futuro aggiungo un quinto scenario e dimentico di
  ## aggiornare il "4", il compilatore rifiuta di compilare: a differenza
  ## di un seq, un array è anche una forma (leggera) di documentazione
  ## verificata dal compilatore.
  newScenario(
    "TRANSFORM-001", "Trasformazione reversibile di dato di test",
    "Applica una trasformazione reversibile (XOR) a una stringa di test " &
    "innocua e ne verifica la ricostruzione esatta.",
    ecTransform,
    @[param("payload", "uname -a"), param("xor_key", "90")]
  ),
  newScenario(
    "ARTIFACT-001", "Ispezione di un artefatto compilato",
    "Analizza le stringhe leggibili presenti in un piccolo binario di " &
    "test, distinguendo cosa è visibile staticamente da cosa richiede " &
    "esecuzione per essere osservato.",
    ecArtifact,
    @[param("target_binary", "loader_test")]
  ),
  newScenario(
    "LIFECYCLE-001", "Ciclo di vita minimo di un programma",
    "Genera la sequenza di eventi avvio -> inizializzazione -> " &
    "esecuzione -> terminazione per un programma sintetico.",
    ecLifecycle,
    @[param("duration_ms", "50")]
  ),
  newScenario(
    "BEHAVIOR-001", "Discovery di sistema da processo inatteso",
    "Simula un'utility di discovery (es. uname) lanciata da un parent " &
    "non presente nella whitelist attesa, per studiare falsi positivi " &
    "e limitazioni della detection corrispondente.",
    ecBehavior,
    @[param("child_process", "uname"), param("parent_process", "loader_test")]
  )
]

proc findScenario*(id: string): Result[Scenario] =
  ## Cerca uno scenario nel catalogo predefinito per id.
  for s in BuiltinScenarios:
    if s.id == id:
      return ok(s)
  err[Scenario]("scenario non trovato: " & id)

proc scenariosByCategory*(category: EventCategory): seq[Scenario] =
  ## Restituisce un seq perché il numero di scenari che corrispondono a una
  ## categoria non è noto a priori (potrebbero essere 0, 1, o molti).
  result = @[]
  for s in BuiltinScenarios:
    if s.category == category:
      result.add(s)
NIMSCENARIOS

echo "==> [6/22] Scrittura purple-team/nim/src/transform_lab.nim"
cat > purple-team/nim/src/transform_lab.nim << 'NIMTRANSFORM'
## transform_lab.nim — Laboratorio A: rappresentazione di dati in memoria e
## trasformazioni reversibili.
##
## Studia: conversione stringa<->byte, trasformazione reversibile (XOR),
## confronto tra rappresentazione originale e trasformata, metadati
## osservabili. SOLO dati di test innocui — questo modulo non esegue mai
## nulla, produce esclusivamente analisi e telemetria.
##
## Nota di design importante (dal quadro concordato): il fatto che un dato
## sia rappresentato in byte o trasformato NON è di per sé un segnale da
## trasformare in detection lato SIEM — qui produciamo solo metadati
## osservabili; è siem/nim_lab_rules.py a decidere, con altro contesto
## (es. provenienza, comportamento circostante), se e quando questo genere
## di dato diventa interessante per un analista.

import std/strutils
import std/json

type
  ByteTransformResult* = object
    originalText*: string
    originalBytes*: seq[uint8]
    transformedBytes*: seq[uint8]
    key*: uint8
    reversible*: bool
    recoveredText*: string

proc toBytes*(s: string): seq[uint8] =
  ## Conversione stringa -> sequenza di byte. `newSeq[uint8](s.len)` alloca
  ## un seq già della lunghezza corretta, evitando `add()` ripetuti.
  result = newSeq[uint8](s.len)
  for i, c in s:
    result[i] = uint8(c)

proc fromBytes*(data: seq[uint8]): string =
  ## Percorso inverso: byte -> stringa.
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b)

proc xorTransform*(data: seq[uint8], key: uint8): seq[uint8] =
  ## XOR è "involutorio": applicarlo due volte con la stessa chiave
  ## restituisce il dato originale. È la trasformazione reversibile più
  ## semplice possibile da studiare, e la stessa usata (con scopo diverso,
  ## offuscamento) nel loader.nim già esistente in purple-team/nim-loaders/.
  result = newSeq[uint8](data.len)
  for i, b in data:
    result[i] = b xor key

proc toHexString*(data: seq[uint8]): string =
  ## Rappresentazione esadecimale leggibile, utile per ispezionare a occhio
  ## una sequenza di byte senza stamparne i caratteri grezzi.
  result = ""
  for b in data:
    result.add(toHex(b.BiggestInt, 2))  # 2 cifre hex per byte, es. "5a"

proc runTransformScenario*(text: string, key: uint8): ByteTransformResult =
  ## Esegue l'intero studio: converte, trasforma, riconverte, confronta.
  let originalBytes = toBytes(text)
  let transformed = xorTransform(originalBytes, key)
  let recoveredBytes = xorTransform(transformed, key)  # stessa chiave -> torna indietro
  let recoveredText = fromBytes(recoveredBytes)

  result = ByteTransformResult(
    originalText: text,
    originalBytes: originalBytes,
    transformedBytes: transformed,
    key: key,
    reversible: recoveredText == text,
    recoveredText: recoveredText
  )

proc toTelemetryFields*(r: ByteTransformResult): JsonNode =
  ## Metadati OSSERVABILI: non il contenuto originale in chiaro, ma
  ## caratteristiche misurabili su di esso — lunghezza, reversibilità,
  ## un prefisso esadecimale limitato per ispezione. Questo è il tipo di
  ## informazione che un sistema di analisi statica potrebbe estrarre da
  ## un artefatto reale, senza eseguirlo.
  let hex = toHexString(r.transformedBytes)
  let hexPrefix = if hex.len > 16: hex[0 ..< 16] else: hex

  result = %*{
    "original_length": r.originalText.len,
    "transformed_length": r.transformedBytes.len,
    "key": r.key.int,
    "reversible": r.reversible,
    "transformed_hex_prefix": hexPrefix
  }
NIMTRANSFORM

echo "==> [7/22] Scrittura purple-team/nim/src/artifact_analysis.nim"
cat > purple-team/nim/src/artifact_analysis.nim << 'NIMARTIFACT'
## artifact_analysis.nim — Analisi statica di artefatti compilati.
##
## Studia: quali stringhe restano leggibili in un binario compilato senza
## eseguirlo (analisi statica), e se un termine cercato compare in chiaro.
## Concettualmente la stessa domanda posta dal check CI già esistente su
## purple-team/nim-loaders/loader_test ("strings | grep uname non deve
## trovarlo"), ma qui come funzione Nim riutilizzabile e testabile invece
## che come singola riga di shell.
##
## Questo modulo LEGGE file dal disco ma non ne esegue mai il contenuto.

import std/os
import std/strutils
import std/json
import ./models

type
  ArtifactReport* = object
    path*: string
    sizeBytes*: int
    extractedStrings*: seq[string]
    containsCleartext*: bool
    searchedTerm*: string

proc extractPrintableStrings*(data: string, minLength: int = 4): seq[string] =
  ## Replica minimale di `strings`(1): individua sequenze contigue di
  ## caratteri ASCII stampabili lunghe almeno `minLength`.
  ##
  ## `{' '..'~'}` è un range di caratteri (da spazio a tilde, cioè tutto lo
  ## stampabile ASCII) usato come "set literal" — l'operatore `in` su un
  ## set di caratteri è O(1), diverso dall'`in` su stringa visto prima.
  result = @[]
  var current = ""
  for ch in data:
    if ch in {' '..'~'}:
      current.add(ch)
    else:
      if current.len >= minLength:
        result.add(current)
      current = ""
  if current.len >= minLength:
    result.add(current)

proc analyzeArtifact*(path: string, searchTerm: string,
                       minLength: int = 4): Result[ArtifactReport] =
  ## Legge un file e verifica se `searchTerm` compare in chiaro tra le
  ## stringhe stampabili estratte. Restituisce Result: un path inesistente
  ## è un errore da gestire esplicitamente, non un report vuoto silenzioso.
  if not fileExists(path):
    return err[ArtifactReport]("file non trovato: " & path)

  let data = readFile(path)
  let strs = extractPrintableStrings(data, minLength)

  var found = false
  let needle = searchTerm.toLowerAscii()
  for s in strs:
    if needle in s.toLowerAscii():
      found = true
      break

  ok(ArtifactReport(
    path: path,
    sizeBytes: data.len,
    extractedStrings: strs,
    containsCleartext: found,
    searchedTerm: searchTerm
  ))

proc toTelemetryFields*(r: ArtifactReport): JsonNode =
  ## Metadati osservabili: dimensione, numero di stringhe estratte, esito
  ## della ricerca. NON il dump completo delle stringhe (rumoroso e in
  ## parte ridondante con il file stesso) — solo ciò che serve a un
  ## analista per giudicare se approfondire.
  %*{
    "size_bytes": r.sizeBytes,
    "extracted_strings_count": r.extractedStrings.len,
    "searched_term": r.searchedTerm,
    "contains_cleartext": r.containsCleartext
  }
NIMARTIFACT

echo "==> [8/22] Scrittura purple-team/nim/src/system_event_lab.nim"
cat > purple-team/nim/src/system_event_lab.nim << 'NIMSYSEVENT'
## system_event_lab.nim — Laboratorio B: eventi di avvio e durata.
##
## Genera la sequenza sintetica avvio -> inizializzazione -> caricamento
## componente -> esecuzione -> terminazione, come telemetria strutturata.
##
## Nessun meccanismo di installazione, persistenza o avvio automatico:
## solo modellazione della sequenza e verifica della sua coerenza, per
## studiare come una detection potrebbe correlare "evento iniziale ->
## sequenza di attività -> risultato -> terminazione".

import std/json
import ./models

type
  LifecycleStage* = enum
    lsStartup = "startup"
    lsInit = "init"
    lsComponentLoad = "component_load"
    lsExecution = "execution"
    lsTermination = "termination"

  LifecycleEvent* = object
    stage*: LifecycleStage
    sequenceNumber*: int
      ## Posizione nella sequenza (0, 1, 2, ...): permette a chi consuma
      ## la telemetria di ricostruire l'ordine anche se gli eventi
      ## arrivassero fuori ordine (es. per latenza di rete diversa).
    detail*: string

proc newLifecycleEvent*(stage: LifecycleStage, sequenceNumber: int,
                         detail: string = ""): LifecycleEvent =
  LifecycleEvent(stage: stage, sequenceNumber: sequenceNumber, detail: detail)

proc generateLifecycle*(componentName: string): seq[LifecycleEvent] =
  ## Sequenza fissa e deterministica: stesso componentName -> stessi eventi,
  ## sempre. Utile per test di regressione e per signal_coverage.nim, che
  ## dovrà confrontare "cosa ci si aspetta" con "cosa viene osservato".
  result = @[
    newLifecycleEvent(lsStartup, 0, "avvio del programma sintetico"),
    newLifecycleEvent(lsInit, 1, "inizializzazione delle risorse"),
    newLifecycleEvent(lsComponentLoad, 2, "caricamento componente: " & componentName),
    newLifecycleEvent(lsExecution, 3, "esecuzione della funzione principale"),
    newLifecycleEvent(lsTermination, 4, "terminazione pulita")
  ]

proc validateSequence*(events: seq[LifecycleEvent]): Result[seq[LifecycleEvent]] =
  ## Verifica che la sequenza sia internamente coerente: numerata in ordine
  ## crescente senza salti, e che l'ULTIMO evento sia davvero una
  ## terminazione (altrimenti la sequenza è "a metà", il che di per sé
  ## potrebbe essere interessante per una detection di correlazione).
  if events.len == 0:
    return err[seq[LifecycleEvent]]("sequenza vuota")

  for i, e in events:
    if e.sequenceNumber != i:
      return err[seq[LifecycleEvent]](
        "sequenceNumber fuori ordine alla posizione " & $i &
        " (atteso " & $i & ", trovato " & $e.sequenceNumber & ")")

  if events[^1].stage != lsTermination:
    ## `events[^1]` è l'ultimo elemento del seq: `^1` è l'operatore Nim di
    ## indicizzazione "dalla fine", equivalente a events[events.len - 1].
    return err[seq[LifecycleEvent]]("la sequenza non termina con lsTermination")

  ok(events)

proc toTelemetryFields*(e: LifecycleEvent): JsonNode =
  %*{
    "stage": $e.stage,
    "sequence_number": e.sequenceNumber,
    "detail": e.detail
  }
NIMSYSEVENT

echo "==> [9/22] Scrittura purple-team/nim/src/behavior_lab.nim"
cat > purple-team/nim/src/behavior_lab.nim << 'NIMBEHAVIOR'
## behavior_lab.nim — Laboratorio D: analisi di comportamenti software.
##
## A differenza di scenarios.nim (che descrive COME costruire un evento),
## questo modulo documenta il comportamento da un punto di vista di
## detection engineering: cosa ci si aspetta, quali segnali produce, quale
## detection dovrebbe scattare, quali falsi positivi sono plausibili e
## quali sono i limiti noti. È un catalogo di DOCUMENTAZIONE strutturata,
## non di generazione di eventi.

import std/json
import ./models

type
  BehaviorProfile* = object
    scenarioId*: string
    expectedBehavior*: string
    signalsProduced*: seq[string]
    telemetryAvailable*: seq[string]
    expectedDetectionId*: string
    possibleFalsePositives*: seq[string]
    limitations*: string

proc newBehaviorProfile*(scenarioId, expectedBehavior: string,
                          signalsProduced, telemetryAvailable: seq[string],
                          expectedDetectionId: string,
                          possibleFalsePositives: seq[string],
                          limitations: string): BehaviorProfile =
  BehaviorProfile(
    scenarioId: scenarioId, expectedBehavior: expectedBehavior,
    signalsProduced: signalsProduced, telemetryAvailable: telemetryAvailable,
    expectedDetectionId: expectedDetectionId,
    possibleFalsePositives: possibleFalsePositives, limitations: limitations
  )

const BuiltinProfiles*: array[1, BehaviorProfile] = [
  newBehaviorProfile(
    "BEHAVIOR-001",
    "Un processo non presente nella whitelist attesa lancia un'utility " &
    "di discovery di sistema (es. uname).",
    @["process_creation event con child_process_name tra le utility di discovery"],
    @["telemetria di processo (Go agent o nim-agent)", "campo parent_process_name"],
    "PROC-001",
    @["automazione legittima (es. Ansible) non ancora presente nella whitelist",
      "script di provisioning interno non catalogato"],
    "La detection dipende interamente dal contenuto della whitelist dei " &
    "parent attesi: un nuovo strumento di automazione legittimo genera un " &
    "falso positivo finché non viene esplicitamente aggiunto alla lista."
  )
]

proc findProfile*(scenarioId: string): Result[BehaviorProfile] =
  for p in BuiltinProfiles:
    if p.scenarioId == scenarioId:
      return ok(p)
  err[BehaviorProfile]("profilo comportamentale non trovato per scenario: " & scenarioId)

proc toDocumentationJson*(p: BehaviorProfile): JsonNode =
  ## A differenza degli altri toTelemetryFields visti finora, qui il JSON
  ## non è "telemetria da inviare al SIEM" ma DOCUMENTAZIONE machine-readable
  ## del comportamento — utile per generare report o alimentare
  ## signal_coverage.nim con i dati attesi da confrontare con l'osservato.
  %*{
    "scenario_id": p.scenarioId,
    "expected_behavior": p.expectedBehavior,
    "signals_produced": p.signalsProduced,
    "telemetry_available": p.telemetryAvailable,
    "expected_detection_id": p.expectedDetectionId,
    "possible_false_positives": p.possibleFalsePositives,
    "limitations": p.limitations
  }
NIMBEHAVIOR

echo "==> [10/22] Scrittura purple-team/nim/src/correlation_lab.nim"
cat > purple-team/nim/src/correlation_lab.nim << 'NIMCORRELATION'
## correlation_lab.nim — Laboratorio E: correlazione di segnali.
##
## Genera SEQUENZE di eventi correlati (evento A + evento B + coerenza
## temporale), non singoli eventi isolati. È l'input concettuale per un
## motore di correlazione lato SIEM (siem/correlation_rules.py), che
## guarda più eventi insieme invece di reagire a un singolo indicatore.

import std/json
import ./models

type
  CorrelationEvent* = object
    eventId*: string
    timestampOffsetMs*: int
      ## Offset in millisecondi RELATIVO al primo evento della sequenza,
      ## non un timestamp assoluto: rende gli scenari deterministici e
      ## facilmente testabili, senza dipendere dall'ora di sistema.
    category*: EventCategory
    fields*: JsonNode

  CorrelationSequence* = object
    id*: string
    description*: string
    events*: seq[CorrelationEvent]

proc newCorrelationEvent*(eventId: string, timestampOffsetMs: int,
                           category: EventCategory,
                           fields: JsonNode): CorrelationEvent =
  CorrelationEvent(eventId: eventId, timestampOffsetMs: timestampOffsetMs,
                    category: category, fields: fields)

proc newCorrelationSequence*(id, description: string,
                              events: seq[CorrelationEvent]): CorrelationSequence =
  CorrelationSequence(id: id, description: description, events: events)

proc isTemporallyCoherent*(s: CorrelationSequence, maxSpanMs: int): bool =
  ## Vero se tutti gli eventi della sequenza cadono entro una finestra
  ## temporale larga al massimo maxSpanMs. Una sequenza "corretta" nei
  ## contenuti ma spalmata su ore non rappresenta più lo stesso segnale.
  if s.events.len == 0:
    return true
  var minOffset = s.events[0].timestampOffsetMs
  var maxOffset = s.events[0].timestampOffsetMs
  for e in s.events:
    if e.timestampOffsetMs < minOffset: minOffset = e.timestampOffsetMs
    if e.timestampOffsetMs > maxOffset: maxOffset = e.timestampOffsetMs
  (maxOffset - minOffset) <= maxSpanMs

proc buildDiscoveryAfterUnexpectedParentSequence*(): CorrelationSequence =
  ## Esempio concreto del punto E del quadro concordato: evento A (spawn di
  ## un processo con parent sconosciuto) + evento B (quello stesso processo
  ## lancia un'utility di discovery) entro una finestra temporale breve.
  ## Nessuno dei due eventi preso da solo è necessariamente interessante:
  ## PROC-001 (lato Python) già segnala evento B da solo con parent non
  ## whitelisted; qui il valore aggiunto è la CATENA — lo stesso processo
  ## sconosciuto che compare e poi fa discovery, entro pochi millisecondi.
  let eventA = newCorrelationEvent(
    "evt-001", 0, ecBehavior,
    %*{"action": "spawn", "process_name": "loader_test",
       "parent_process_name": "unknown"}
  )
  let eventB = newCorrelationEvent(
    "evt-002", 150, ecBehavior,
    %*{"action": "spawn", "process_name": "uname",
       "parent_process_name": "loader_test"}
  )
  newCorrelationSequence(
    "CORR-001",
    "Processo con parent sconosciuto seguito a breve da discovery di sistema",
    @[eventA, eventB]
  )

proc toTelemetryFields*(s: CorrelationSequence): JsonNode =
  ## Costruisce un JArray esplicitamente (invece che con %* su un seq
  ## intero) perché ogni CorrelationEvent contiene già un JsonNode
  ## (`fields`) nidificato — serializzarlo con %* diretto è più leggibile
  ## fatto elemento per elemento.
  var eventsJson = newJArray()
  for e in s.events:
    eventsJson.add(%*{
      "event_id": e.eventId,
      "timestamp_offset_ms": e.timestampOffsetMs,
      "category": $e.category,
      "fields": e.fields
    })

  %*{
    "sequence_id": s.id,
    "description": s.description,
    "event_count": s.events.len,
    "events": eventsJson
  }
NIMCORRELATION

echo "==> [11/22] Scrittura purple-team/nim/src/signal_coverage.nim"
cat > purple-team/nim/src/signal_coverage.nim << 'NIMSIGNALCOV'
## signal_coverage.nim — Laboratorio C: segnali e copertura.
##
## Per ogni scenario, registra l'intera catena concettuale:
##   scenario -> segnale generato -> telemetria raccolta -> normalizzato
##   dal SIEM -> regola applicabile -> detection scattata -> livello di
##   visibilità (completa / parziale / assente).
##
## La visibilità NON si assegna a mano: si calcola dagli altri campi, per
## evitare che i due valori possano andare fuori sincrono tra loro.

import std/json

type
  VisibilityLevel* = enum
    vlFull = "full"        ## telemetria raccolta + normalizzata + regola + detection scattata
    vlPartial = "partial"  ## qualcosa è osservabile, ma la catena non è completa
    vlNone = "none"        ## nessuna visibilità: il comportamento è invisibile allo stack attuale

  CoverageEntry* = object
    scenarioId*: string
    signalGenerated*: string
    telemetryCollected*: bool
    normalizedBySiem*: bool
    applicableRuleId*: string
      ## stringa vuota = nessuna regola del SIEM si applica a questo segnale
    detectionFired*: bool
    visibility*: VisibilityLevel

proc computeVisibility(telemetryCollected, normalizedBySiem: bool,
                        applicableRuleId: string, detectionFired: bool): VisibilityLevel =
  if telemetryCollected and normalizedBySiem and
     applicableRuleId.len > 0 and detectionFired:
    vlFull
  elif telemetryCollected or normalizedBySiem:
    vlPartial
  else:
    vlNone

proc newCoverageEntry*(scenarioId, signalGenerated: string,
                        telemetryCollected, normalizedBySiem: bool,
                        applicableRuleId: string,
                        detectionFired: bool): CoverageEntry =
  ## `computeVisibility` è una proc privata (nessun `*`): usata solo qui
  ## dentro il modulo, non ha motivo di essere esportata.
  CoverageEntry(
    scenarioId: scenarioId,
    signalGenerated: signalGenerated,
    telemetryCollected: telemetryCollected,
    normalizedBySiem: normalizedBySiem,
    applicableRuleId: applicableRuleId,
    detectionFired: detectionFired,
    visibility: computeVisibility(telemetryCollected, normalizedBySiem,
                                   applicableRuleId, detectionFired)
  )

proc toTelemetryFields*(e: CoverageEntry): JsonNode =
  %*{
    "scenario_id": e.scenarioId,
    "signal_generated": e.signalGenerated,
    "telemetry_collected": e.telemetryCollected,
    "normalized_by_siem": e.normalizedBySiem,
    "applicable_rule_id": e.applicableRuleId,
    "detection_fired": e.detectionFired,
    "visibility": $e.visibility
  }

proc buildCoverageMatrix*(entries: seq[CoverageEntry]): JsonNode =
  ## Aggrega più CoverageEntry in un'unica matrice, con un piccolo riepilogo
  ## calcolato (quanti scenari sono completamente visibili) — utile per
  ## avere un colpo d'occhio senza dover contare a mano le singole voci.
  var arr = newJArray()
  var fullyVisibleCount = 0
  for e in entries:
    arr.add(toTelemetryFields(e))
    if e.visibility == vlFull:
      inc fullyVisibleCount

  %*{
    "coverage_matrix": arr,
    "total_scenarios": entries.len,
    "fully_visible_count": fullyVisibleCount
  }
NIMSIGNALCOV

echo "==> [12/22] Scrittura purple-team/nim/src/main.nim"
cat > purple-team/nim/src/main.nim << 'NIMMAIN'
## main.nim — Runner principale del laboratorio Purple Team/SIEM in Nim.
##
## Esegue in sequenza tutti i laboratori didattici, stampa la telemetria
## prodotta (sempre) e, se richiesto (--send o variabile d'ambiente
## SIEM_INGEST_URL impostata), la invia al SIEM tramite sender.nim.
##
## Uso:
##   ./main                    # stampa la telemetria di ogni laboratorio
##   ./main --send             # inoltre la invia a SIEM_INGEST_URL
##
## Variabili d'ambiente lette (stesso schema del Go agent):
##   SIEM_INGEST_URL   default: http://localhost:5000/api/v1/ingress
##   SIEM_AGENT_TOKEN  default: "" (nessuna autenticazione)
##   NIM_AGENT_ID      default: "nim-agent-01"
##   NIM_HOSTNAME      default: hostname() di sistema

import std/os
import std/json
import std/times

import ./models
import ./telemetry
import ./sender
import ./scenarios
import ./transform_lab
import ./system_event_lab
import ./behavior_lab
import ./signal_coverage
import ./correlation_lab

proc getEnvOr(key, fallback: string): string =
  let v = getEnv(key)
  if v.len > 0: v else: fallback

proc currentTimestamp(): string =
  now().utc.format("yyyy-MM-dd'T'HH:mm:ss'Z'")

proc emit(payload: JsonNode, doSend: bool, cfg: SenderConfig) =
  ## Punto unico di uscita per ogni evento generato dai laboratori: stampa
  ## sempre (per ispezione immediata), e invia solo se richiesto.
  echo serialize(payload)
  if doSend:
    let res = send(cfg, serialize(payload))
    if res.isOk:
      stderr.writeLine("  -> inviato al SIEM, status " & $res.value)
    else:
      stderr.writeLine("  -> ERRORE invio al SIEM: " & res.error)

proc runAll(agentId, hostname: string, doSend: bool, cfg: SenderConfig) =
  let ts = currentTimestamp()

  # --- Laboratorio A: trasformazione reversibile ---
  let transformScenario = findScenario("TRANSFORM-001")
  if transformScenario.isOk:
    let payloadParam = getParam(transformScenario.value, "payload")
    let text = if payloadParam.isOk: payloadParam.value else: "uname -a"
    let r = runTransformScenario(text, 0x5A)
    let fields = transform_lab.toTelemetryFields(r)
    let payload = buildGenericEvent(ecTransform, "transform.reversible_applied",
      "trasformazione reversibile applicata a dato di test", fields, ts)
    emit(payload, doSend, cfg)

  # --- Laboratorio B: ciclo di vita ---
  let lifecycle = generateLifecycle("nim-lab-component")
  let validated = validateSequence(lifecycle)
  if validated.isOk:
    for e in validated.value:
      let fields = system_event_lab.toTelemetryFields(e)
      let payload = buildGenericEvent(ecLifecycle, "lifecycle." & $e.stage,
        e.detail, fields, ts)
      emit(payload, doSend, cfg)

  # --- Laboratorio D: profilo comportamentale (documentazione, non evento) ---
  let profile = findProfile("BEHAVIOR-001")
  if profile.isOk:
    let doc = toDocumentationJson(profile.value)
    stderr.writeLine("--- Profilo comportamentale BEHAVIOR-001 ---")
    stderr.writeLine(serialize(doc))

  # --- Laboratorio E: sequenza correlata ---
  let corrSeq = buildDiscoveryAfterUnexpectedParentSequence()

  # Ogni evento della sequenza viene inviato ANCHE come evento "behavior"
  # a sé stante: esattamente come farebbe il Go agent con la telemetria di
  # processo individuale. Questo permette a NIM-BEHAVIOR-001 (che valuta UN
  # evento alla volta) di avere davvero occasione di scattare, in aggiunta
  # alla sequenza aggregata sotto, che alimenta invece CORR-001 (il motore
  # di correlazione separato).
  for subEvent in corrSeq.events:
    let action = subEvent.fields["action"].getStr()
    let payload = buildGenericEvent(subEvent.category, "behavior." & action,
      "evento individuale della sequenza " & corrSeq.id, subEvent.fields, ts)
    emit(payload, doSend, cfg)

  if isTemporallyCoherent(corrSeq, maxSpanMs = 1000):
    let fields = correlation_lab.toTelemetryFields(corrSeq)
    let payload = buildGenericEvent(ecCorrelation, "correlation.sequence_observed",
      corrSeq.description, fields, ts)
    emit(payload, doSend, cfg)

  # --- Laboratorio C: matrice di copertura di quanto appena eseguito ---
  let coverage = @[
    newCoverageEntry("TRANSFORM-001", "byte_transform event",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "", detectionFired = false),
    newCoverageEntry("LIFECYCLE-001", "lifecycle sequence",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "", detectionFired = false),
    newCoverageEntry("BEHAVIOR-001", "process_creation event",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "PROC-001", detectionFired = true),
    newCoverageEntry("CORR-001", "correlated sequence",
                      telemetryCollected = true, normalizedBySiem = true,
                      applicableRuleId = "", detectionFired = false)
  ]
  let matrix = buildCoverageMatrix(coverage)
  stderr.writeLine("--- Matrice di copertura ---")
  stderr.writeLine(serialize(matrix))

when isMainModule:
  let args = commandLineParams()
  let doSend = "--send" in args

  let agentId = getEnvOr("NIM_AGENT_ID", "nim-agent-01")
  let hostname = getEnvOr("NIM_HOSTNAME", "nim-lab-host")
  let endpoint = getEnvOr("SIEM_INGEST_URL", "http://localhost:5000/api/v1/ingress")
  let token = getEnvOr("SIEM_AGENT_TOKEN", "")
  let cfg = newSenderConfig(endpoint, token)

  runAll(agentId, hostname, doSend, cfg)
NIMMAIN

echo "==> [13/22] Scrittura purple-team/nim/tests/test_models.nim"
cat > purple-team/nim/tests/test_models.nim << 'NIMTESTMODELS'
## test_models.nim — Test per src/models.nim
##
## Usa std/unittest, il framework di test incluso nella libreria standard
## di Nim: `suite` raggruppa i test in un blocco con un nome, `test` è un
## singolo caso, `check` è l'assert che, se falso, fa fallire il test
## mostrando l'espressione esatta che non ha funzionato (a differenza di un
## semplice `assert`, `check` continua a eseguire gli altri check nello
## stesso test invece di interrompersi al primo fallimento).

import std/unittest
import std/strutils
import ../src/models

suite "EventCategory (enum)":
  test "ogni categoria ha la rappresentazione stringa attesa":
    check $ecProcess == "process"
    check $ecTransform == "transform"
    check $ecCorrelation == "correlation"

suite "costruzione modelli":
  test "newProcessContext popola tutti i campi richiesti":
    let pc = newProcessContext(
      pid = 1234, ppid = 1,
      processName = "bash", executablePath = "/bin/bash",
      commandLine = "bash -c foo", parentProcessName = "systemd"
    )
    check pc.pid == 1234
    check pc.ppid == 1
    check pc.processName == "bash"
    check pc.sha256 == ""  # valore di default non passato

  test "newProcessContext con sha256 esplicito":
    let pc = newProcessContext(
      pid = 1, ppid = 0, processName = "x", executablePath = "/x",
      commandLine = "x", parentProcessName = "y", sha256 = "abc123"
    )
    check pc.sha256 == "abc123"

  test "newTelemetry assembla correttamente l'envelope":
    let pc = newProcessContext(1, 0, "loader_test", "/tmp/loader_test",
                                "loader_test", "bash")
    let ed = EventData(action: "spawn", childProcessName: "uname")
    let t = newTelemetry("agent-01", "host-01", "2026-07-17T10:00:00Z",
                          "process_creation", ecProcess, pc, ed)

    check t.schemaVersion == SchemaVersion
    check t.source == "nim-agent"
    check t.category == ecProcess
    check t.agentId == "agent-01"
    check t.eventData.action == "spawn"

suite "validate (Result generico + error handling)":
  test "telemetria valida ritorna isOk true":
    let pc = newProcessContext(100, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("agent-01", "host-01", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == true
    check res.value.agentId == "agent-01"

  test "agentId vuoto produce errore":
    let pc = newProcessContext(100, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("", "host-01", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == false
    check "agentId" in res.error

  test "hostname vuoto produce errore":
    let pc = newProcessContext(100, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("agent-01", "", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == false
    check "hostname" in res.error

  test "pid negativo produce errore":
    let pc = newProcessContext(-5, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("agent-01", "host-01", "ts", "et", ecProcess, pc,
                          EventData(action: "spawn"))
    let res = validate(t)
    check res.isOk == false
    check "pid" in res.error

  test "input multipli: piu' telemetrie in sequenza restano indipendenti":
    # Verifica che costruire piu' object in sequenza non condivida stato
    # (nessuna variabile globale mutabile nascosta in models.nim).
    var results: seq[Result[Telemetry]] = @[]
    for i in 0 .. 4:
      let pc = newProcessContext(i, 0, "proc" & $i, "/bin/proc" & $i,
                                  "proc" & $i, "parent")
      let t = newTelemetry("agent-" & $i, "host-" & $i, "ts", "et",
                            ecProcess, pc, EventData(action: "spawn"))
      results.add(validate(t))

    check results.len == 5
    for i, r in results:
      check r.isOk == true
      check r.value.agentId == "agent-" & $i

suite "Result[T] generico (senza Telemetry)":
  test "ok/err funzionano anche con tipi primitivi":
    let goodInt: Result[int] = ok(42)
    let badInt: Result[int] = err[int]("valore non valido")

    check goodInt.isOk == true
    check goodInt.value == 42
    check badInt.isOk == false
    check badInt.error == "valore non valido"

  test "ok/err funzionano con string":
    let r: Result[string] = ok("ciao")
    check r.isOk == true
    check r.value == "ciao"
NIMTESTMODELS

echo "==> [14/22] Scrittura purple-team/nim/tests/test_telemetry.nim"
cat > purple-team/nim/tests/test_telemetry.nim << 'NIMTESTTELEMETRY'
## test_telemetry.nim — Test per src/telemetry.nim

import std/unittest
import std/json
import ../src/models
import ../src/telemetry

suite "toIngressPayload — telemetria di processo":
  test "forma base: campi obbligatori sempre presenti":
    let pc = newProcessContext(100, 1, "bash", "/bin/bash", "bash -c x", "systemd")
    let ed = EventData(action: "exec")
    let t = newTelemetry("agent-01", "host-01", "2026-07-17T10:00:00Z",
                          "process_creation", ecProcess, pc, ed)
    let payload = toIngressPayload(t)

    check payload["timestamp"].getStr() == "2026-07-17T10:00:00Z"
    check payload["source"].getStr() == "nim-agent"
    check payload["category"].getStr() == "process"
    check payload["event_type"].getStr() == "process_creation"
    check payload["fields"]["agent_id"].getStr() == "agent-01"
    check payload["fields"]["pid"].getInt() == 100

  test "campi opzionali ASSENTI quando vuoti (omitempty)":
    let pc = newProcessContext(1, 0, "p", "/p", "p", "parent")  # sha256 default ""
    let ed = EventData(action: "spawn")  # childProcessName/CommandLine default ""
    let t = newTelemetry("a", "h", "ts", "et", ecProcess, pc, ed)
    let payload = toIngressPayload(t)

    check not payload["fields"].hasKey("sha256")
    check not payload["fields"].hasKey("child_process_name")
    check not payload["fields"].hasKey("child_command_line")

  test "campi opzionali PRESENTI quando valorizzati":
    let pc = newProcessContext(1, 0, "p", "/p", "p", "parent", sha256 = "deadbeef")
    let ed = EventData(action: "spawn", childProcessName: "uname",
                        childCommandLine: "uname -a")
    let t = newTelemetry("a", "h", "ts", "et", ecProcess, pc, ed)
    let payload = toIngressPayload(t)

    check payload["fields"]["sha256"].getStr() == "deadbeef"
    check payload["fields"]["child_process_name"].getStr() == "uname"
    check payload["fields"]["child_command_line"].getStr() == "uname -a"

suite "buildGenericEvent — laboratori non-processo":
  test "categoria transform con fields arbitrarie":
    let fields = %*{"original_len": 8, "transformed_len": 8, "reversible": true}
    let payload = buildGenericEvent(ecTransform, "byte_transform.applied",
                                     "trasformazione reversibile applicata a dato di test",
                                     fields, "2026-07-17T11:00:00Z")

    check payload["category"].getStr() == "transform"
    check payload["source"].getStr() == "nim-agent"
    check payload["fields"]["original_len"].getInt() == 8
    check payload["fields"]["reversible"].getBool() == true

  test "source personalizzabile (es. per differenziare scenari nello stesso lab)":
    let fields = %*{"note": "test"}
    let payload = buildGenericEvent(ecLifecycle, "lifecycle.start", "avvio",
                                     fields, "ts", source = "nim-lifecycle-lab")
    check payload["source"].getStr() == "nim-lifecycle-lab"

  test "fields vuote (oggetto JSON vuoto) sono accettate":
    let payload = buildGenericEvent(ecSignal, "signal.observed", "segnale osservato",
                                     %*{}, "ts")
    check payload["fields"].kind == JObject
    check payload["fields"].len == 0

suite "serialize + parseIngressPayload (round-trip)":
  test "serialize produce una stringa JSON valida che si ri-parsa identica":
    let pc = newProcessContext(5, 1, "p", "/p", "p", "parent")
    let t = newTelemetry("a", "h", "ts", "et", ecProcess, pc, EventData(action: "exec"))
    let original = toIngressPayload(t)
    let asString = serialize(original)

    let reparsed = parseIngressPayload(asString)
    check reparsed.isOk == true
    check reparsed.value["fields"]["agent_id"].getStr() == "a"
    check reparsed.value["category"].getStr() == "process"

  test "JSON malformato produce errore gestito, non un crash":
    let res = parseIngressPayload("{questo non e' json valido")
    check res.isOk == false
    check res.error.len > 0

  test "stringa vuota e' JSON malformato":
    let res = parseIngressPayload("")
    check res.isOk == false

  test "input multipli: piu' round-trip in sequenza restano indipendenti":
    for i in 0 .. 3:
      let fields = %*{"index": i}
      let payload = buildGenericEvent(ecArtifact, "artifact.inspected",
                                       "ispezione artefatto #" & $i, fields, "ts")
      let reparsed = parseIngressPayload(serialize(payload))
      check reparsed.isOk == true
      check reparsed.value["fields"]["index"].getInt() == i
NIMTESTTELEMETRY

echo "==> [15/22] Scrittura purple-team/nim/tests/test_sender.nim"
cat > purple-team/nim/tests/test_sender.nim << 'NIMTESTSENDER'
## test_sender.nim — Test per src/sender.nim
##
## Nessuno di questi test tocca la rete: 'transport' e 'sleepFn' sono finti,
## iniettati al posto delle versioni reali. Verifichiamo solo la LOGICA di
## retry/backoff, non il comportamento di una vera libreria HTTP.

import std/unittest
import std/strutils
import ../src/models
import ../src/sender

suite "send — successo":
  test "risposta 200 al primo tentativo: nessun retry":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == true
    check res.value == 200
    check callCount == 1  # nessun retry necessario

suite "send — errore client (4xx), nessun retry":
  test "401 non autorizzato: fallisce subito, un solo tentativo":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 401, body: "unauthorized")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == false
    check "401" in res.error
    check callCount == 1  # NIENTE retry su 4xx

suite "send — errore server (5xx), retry con backoff":
  test "500 persistente esaurisce tutti i tentativi (maxRetries + 1 chiamate)":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 500, body: "internal error")

    var sleepCalls: seq[int] = @[]
    proc fakeSleep(ms: int) = sleepCalls.add(ms)

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3,
                              retryBaseDelayMs = 100)
    let res = send(cfg, "{}", transport = fakeTransport, sleepFn = fakeSleep)

    check res.isOk == false
    check callCount == 4  # tentativo iniziale + 3 retry
    check sleepCalls == @[100, 200, 400]  # backoff esponenziale: 100*2^(n-1)

  test "successo al secondo tentativo dopo un primo 500":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      if callCount == 1:
        HttpResult(code: 500, body: "temporary")
      else:
        HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3,
                              retryBaseDelayMs = 10)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == true
    check res.value == 200
    check callCount == 2

suite "send — errore di trasporto (code 0, es. connessione rifiutata)":
  test "code 0 viene trattato come recuperabile (retry), non come 4xx":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 0, body: "connection refused")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 2,
                              retryBaseDelayMs = 10)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == false
    check callCount == 3  # tentativo iniziale + 2 retry, come un 5xx

suite "send — input vuoti":
  test "body vuoto viene comunque inviato (non e' compito di sender.nim validarlo)":
    var receivedBody = ""
    proc fakeTransport(url, body, token: string): HttpResult =
      receivedBody = body
      HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress")
    let res = send(cfg, "", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == true
    check receivedBody == ""

  test "agentToken vuoto viene comunque passato al transport":
    var receivedToken = "non-toccato"
    proc fakeTransport(url, body, token: string): HttpResult =
      receivedToken = token
      HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress", agentToken = "")
    discard send(cfg, "{}", transport = fakeTransport,
                 sleepFn = proc(ms: int) = discard)

    check receivedToken == ""
NIMTESTSENDER

echo "==> [16/22] Scrittura purple-team/nim/tests/test_scenarios.nim"
cat > purple-team/nim/tests/test_scenarios.nim << 'NIMTESTSCEN'
## test_scenarios.nim — Test per src/scenarios.nim

import std/unittest
import ../src/models
import ../src/scenarios

suite "catalogo BuiltinScenarios":
  test "il catalogo contiene esattamente 4 scenari (array a dimensione fissa)":
    check BuiltinScenarios.len == 4

  test "ogni scenario ha id e categoria coerenti":
    for s in BuiltinScenarios:
      check s.id.len > 0
      check s.name.len > 0

suite "findScenario":
  test "trova uno scenario esistente per id":
    let res = findScenario("TRANSFORM-001")
    check res.isOk == true
    check res.value.category == ecTransform

  test "scenario inesistente produce errore, non un valore vuoto":
    let res = findScenario("NON-ESISTE-999")
    check res.isOk == false

suite "getParam":
  test "recupera un parametro esistente":
    let res = findScenario("TRANSFORM-001")
    check res.isOk == true
    let p = getParam(res.value, "xor_key")
    check p.isOk == true
    check p.value == "90"

  test "parametro inesistente produce errore":
    let res = findScenario("TRANSFORM-001")
    let p = getParam(res.value, "chiave_inventata")
    check p.isOk == false

suite "scenariosByCategory":
  test "categoria con esattamente uno scenario":
    let found = scenariosByCategory(ecArtifact)
    check found.len == 1
    check found[0].id == "ARTIFACT-001"

  test "categoria senza scenari restituisce seq vuoto, non un errore":
    let found = scenariosByCategory(ecCorrelation)
    check found.len == 0
NIMTESTSCEN

echo "==> [17/22] Scrittura purple-team/nim/tests/test_transform_lab.nim"
cat > purple-team/nim/tests/test_transform_lab.nim << 'NIMTESTTRANSFORM'
## test_transform_lab.nim — Test per src/transform_lab.nim

import std/unittest
import std/json
import std/strutils
import ../src/transform_lab

suite "toBytes / fromBytes — conversione base":
  test "round-trip stringa -> byte -> stringa restituisce l'originale":
    let original = "uname -a"
    let bytes = toBytes(original)
    check bytes.len == original.len
    check fromBytes(bytes) == original

  test "stringa vuota produce seq di byte vuoto":
    let bytes = toBytes("")
    check bytes.len == 0
    check fromBytes(bytes) == ""

suite "xorTransform — trasformazione reversibile":
  test "applicare la stessa chiave due volte restituisce il dato originale":
    let original = toBytes("test deterministico")
    let once = xorTransform(original, 0x5A)
    let twice = xorTransform(once, 0x5A)
    check twice == original

  test "la trasformazione cambia effettivamente i dati (non e' un no-op)":
    let original = toBytes("dato di prova")
    let transformed = xorTransform(original, 0x5A)
    check transformed != original

  test "chiave diversa NON recupera il dato originale":
    let original = toBytes("dato di prova")
    let transformed = xorTransform(original, 0x5A)
    let wrongRecovery = xorTransform(transformed, 0x11)
    check wrongRecovery != original

  test "seq vuoto resta vuoto dopo la trasformazione":
    let empty: seq[uint8] = @[]
    check xorTransform(empty, 0x5A).len == 0

suite "runTransformScenario — studio completo":
  test "scenario deterministico: stessa chiave e stesso testo ripetuti danno risultato identico":
    let r1 = runTransformScenario("dato di test", 0x5A)
    let r2 = runTransformScenario("dato di test", 0x5A)
    check r1.transformedBytes == r2.transformedBytes
    check r1.reversible == r2.reversible

  test "il risultato e' marcato reversibile e recovered == originale":
    let r = runTransformScenario("uname -a", 0x5A)
    check r.reversible == true
    check r.recoveredText == "uname -a"

  test "testo vuoto e' comunque uno scenario valido (deterministico)":
    let r = runTransformScenario("", 0x5A)
    check r.reversible == true
    check r.originalBytes.len == 0

suite "toTelemetryFields — metadati osservabili":
  test "i campi riportano lunghezza e reversibilita', non il testo in chiaro":
    let r = runTransformScenario("uname -a", 0x5A)
    let fields = toTelemetryFields(r)

    check fields["original_length"].getInt() == 8
    check fields["reversible"].getBool() == true
    check fields["key"].getInt() == 0x5A
    check not fields.hasKey("original_text")  # il testo in chiaro non è un metadato

  test "il prefisso hex e' limitato anche per input lunghi":
    let longText = "x".repeat(100)
    let r = runTransformScenario(longText, 0x5A)
    let fields = toTelemetryFields(r)
    check fields["transformed_hex_prefix"].getStr().len <= 16
NIMTESTTRANSFORM

echo "==> [18/22] Scrittura purple-team/nim/tests/test_artifact_analysis.nim"
cat > purple-team/nim/tests/test_artifact_analysis.nim << 'NIMTESTARTIFACT'
## test_artifact_analysis.nim — Test per src/artifact_analysis.nim
##
## A differenza degli altri test, questi girano contro DUE BINARI VERI,
## già compilati in tests/fixtures/: uno contiene "uname" in chiaro nel
## proprio codice sorgente, l'altro la stessa parola offuscata via XOR
## (stesso schema di purple-team/nim-loaders/loader.nim). Questo verifica
## che analyzeArtifact distingua davvero i due casi, non solo su dati finti.

import std/unittest
import std/os
import std/strutils
import std/json
import ../src/artifact_analysis

const FixturesDir = currentSourcePath().parentDir() / "fixtures"
const PlaintextBinary = FixturesDir / "plaintext_sample"
const ObfuscatedBinary = FixturesDir / "obfuscated_sample"

suite "extractPrintableStrings — funzione base":
  test "estrae solo sequenze abbastanza lunghe":
    let data = "ab\x00\x00\x00cdefgh\x01\x01xy"
    let strs = extractPrintableStrings(data, minLength = 4)
    check "cdefgh" in strs
    check "ab" notin strs   # troppo corta (< 4)
    check "xy" notin strs   # troppo corta (< 4)

  test "input vuoto produce seq vuoto":
    check extractPrintableStrings("").len == 0

  test "dato interamente non stampabile produce seq vuoto":
    check extractPrintableStrings("\x00\x01\x02\x03").len == 0

suite "analyzeArtifact — file inesistente":
  test "path inesistente produce errore, non un report vuoto":
    let res = analyzeArtifact("/percorso/che/non/esiste/xyz", "uname")
    check res.isOk == false
    check "non trovato" in res.error

suite "analyzeArtifact — binario con stringa in chiaro":
  test "'uname' viene trovato in chiaro":
    let res = analyzeArtifact(PlaintextBinary, "uname")
    check res.isOk == true
    check res.value.containsCleartext == true
    check res.value.sizeBytes > 0
    check res.value.extractedStrings.len > 0

suite "analyzeArtifact — binario XOR-offuscato":
  test "'uname' NON viene trovato in chiaro (era offuscato in fase di compilazione)":
    let res = analyzeArtifact(ObfuscatedBinary, "uname")
    check res.isOk == true
    check res.value.containsCleartext == false
    ## Questo e' esattamente cio' che il job CI esistente verifica con
    ## `strings loader_test | grep -qi uname` — qui la stessa verifica
    ## e' una funzione Nim testabile indipendentemente dalla CI.

  test "la ricerca e' case-insensitive":
    let res = analyzeArtifact(PlaintextBinary, "UNAME")
    check res.isOk == true
    check res.value.containsCleartext == true

suite "toTelemetryFields — metadati, non dump completo":
  test "i campi non includono la lista intera delle stringhe estratte":
    let res = analyzeArtifact(PlaintextBinary, "uname")
    let fields = toTelemetryFields(res.value)
    check not fields.hasKey("extracted_strings")
    check fields["extracted_strings_count"].getInt() > 0
    check fields["contains_cleartext"].getBool() == true
NIMTESTARTIFACT

echo "==> [19/22] Scrittura purple-team/nim/tests/test_system_event_lab.nim"
cat > purple-team/nim/tests/test_system_event_lab.nim << 'NIMTESTSYSEVENT'
## test_system_event_lab.nim — Test per src/system_event_lab.nim

import std/unittest
import std/strutils
import std/json
import ../src/system_event_lab

suite "generateLifecycle — sequenza deterministica":
  test "produce esattamente 5 eventi nell'ordine atteso":
    let events = generateLifecycle("componente-test")
    check events.len == 5
    check events[0].stage == lsStartup
    check events[1].stage == lsInit
    check events[2].stage == lsComponentLoad
    check events[3].stage == lsExecution
    check events[4].stage == lsTermination

  test "stesso componentName produce sempre la stessa sequenza":
    let a = generateLifecycle("x")
    let b = generateLifecycle("x")
    check a == b

  test "il nome del componente compare nel dettaglio del caricamento":
    let events = generateLifecycle("mio-componente")
    check "mio-componente" in events[2].detail

suite "validateSequence — sequenza valida":
  test "una sequenza generata normalmente e' valida":
    let events = generateLifecycle("x")
    let res = validateSequence(events)
    check res.isOk == true
    check res.value.len == 5

suite "validateSequence — sequenza vuota":
  test "seq vuoto produce errore":
    let res = validateSequence(@[])
    check res.isOk == false
    check "vuota" in res.error

suite "validateSequence — sequenza rotta (input costruiti a mano)":
  test "sequenceNumber fuori ordine viene rilevato":
    let broken = @[
      newLifecycleEvent(lsStartup, 0),
      newLifecycleEvent(lsInit, 5),  # salto: dovrebbe essere 1
      newLifecycleEvent(lsTermination, 2)
    ]
    let res = validateSequence(broken)
    check res.isOk == false
    check "fuori ordine" in res.error

  test "sequenza che non termina con lsTermination viene rilevata":
    let incomplete = @[
      newLifecycleEvent(lsStartup, 0),
      newLifecycleEvent(lsInit, 1),
      newLifecycleEvent(lsExecution, 2)
      # manca la terminazione: sequenza "a meta'"
    ]
    let res = validateSequence(incomplete)
    check res.isOk == false
    check "lsTermination" in res.error or "terminazione" in res.error

  test "singolo evento di terminazione e' una sequenza valida (caso limite)":
    let single = @[newLifecycleEvent(lsTermination, 0)]
    let res = validateSequence(single)
    check res.isOk == true

suite "toTelemetryFields":
  test "il campo stage e' la rappresentazione stringa dell'enum":
    let e = newLifecycleEvent(lsExecution, 3, "dettaglio di test")
    let fields = toTelemetryFields(e)
    check fields["stage"].getStr() == "execution"
    check fields["sequence_number"].getInt() == 3
    check fields["detail"].getStr() == "dettaglio di test"
NIMTESTSYSEVENT

echo "==> [20/22] Scrittura purple-team/nim/tests/test_behavior_lab.nim"
cat > purple-team/nim/tests/test_behavior_lab.nim << 'NIMTESTBEHAVIOR'
## test_behavior_lab.nim — Test per src/behavior_lab.nim

import std/unittest
import std/json
import ../src/behavior_lab

suite "findProfile":
  test "trova un profilo esistente":
    let res = findProfile("BEHAVIOR-001")
    check res.isOk == true
    check res.value.expectedDetectionId == "PROC-001"

  test "profilo inesistente produce errore":
    let res = findProfile("NON-ESISTE")
    check res.isOk == false

suite "toDocumentationJson":
  test "tutti i campi documentali sono presenti nel JSON":
    let res = findProfile("BEHAVIOR-001")
    let doc = toDocumentationJson(res.value)

    check doc["scenario_id"].getStr() == "BEHAVIOR-001"
    check doc["expected_detection_id"].getStr() == "PROC-001"
    check doc["signals_produced"].len > 0
    check doc["possible_false_positives"].len > 0
    check doc["limitations"].getStr().len > 0
NIMTESTBEHAVIOR

echo "==> [21/22] Scrittura purple-team/nim/tests/test_correlation_lab.nim"
cat > purple-team/nim/tests/test_correlation_lab.nim << 'NIMTESTCORR'
## test_correlation_lab.nim — Test per src/correlation_lab.nim

import std/unittest
import std/json
import ../src/models
import ../src/correlation_lab

suite "isTemporallyCoherent":
  test "sequenza vuota e' sempre coerente":
    let empty = newCorrelationSequence("X", "vuota", @[])
    check isTemporallyCoherent(empty, 1000) == true

  test "eventi entro la finestra sono coerenti":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check isTemporallyCoherent(s, 1000) == true   # 150ms di span, finestra 1000ms

  test "eventi fuori dalla finestra NON sono coerenti":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check isTemporallyCoherent(s, 100) == false   # 150ms di span, finestra 100ms

  test "un singolo evento e' sempre coerente (span zero)":
    let single = newCorrelationSequence("X", "singolo",
      @[newCorrelationEvent("e1", 0, ecBehavior, %*{"a": 1})])
    check isTemporallyCoherent(single, 0) == true

suite "buildDiscoveryAfterUnexpectedParentSequence":
  test "produce esattamente 2 eventi in ordine temporale":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check s.events.len == 2
    check s.events[0].timestampOffsetMs < s.events[1].timestampOffsetMs

  test "il secondo evento referenzia lo stesso processo lanciato dal primo":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    check s.events[0].fields["process_name"].getStr() ==
          s.events[1].fields["parent_process_name"].getStr()

suite "toTelemetryFields":
  test "serializza correttamente numero e contenuto degli eventi":
    let s = buildDiscoveryAfterUnexpectedParentSequence()
    let fields = toTelemetryFields(s)

    check fields["sequence_id"].getStr() == "CORR-001"
    check fields["event_count"].getInt() == 2
    check fields["events"].len == 2
    check fields["events"][0]["event_id"].getStr() == "evt-001"
    check fields["events"][1]["fields"]["process_name"].getStr() == "uname"
NIMTESTCORR

echo "==> [22/22] Scrittura purple-team/nim/tests/test_signal_coverage.nim"
cat > purple-team/nim/tests/test_signal_coverage.nim << 'NIMTESTSIGCOV'
## test_signal_coverage.nim — Test per src/signal_coverage.nim

import std/unittest
import std/json
import ../src/signal_coverage

suite "newCoverageEntry — visibilita' calcolata automaticamente":
  test "catena completa -> visibilita' full":
    let e = newCoverageEntry("BEHAVIOR-001", "process_creation event",
                              telemetryCollected = true, normalizedBySiem = true,
                              applicableRuleId = "PROC-001", detectionFired = true)
    check e.visibility == vlFull

  test "telemetria raccolta ma nessuna regola applicabile -> partial":
    let e = newCoverageEntry("TRANSFORM-001", "byte_transform event",
                              telemetryCollected = true, normalizedBySiem = true,
                              applicableRuleId = "", detectionFired = false)
    check e.visibility == vlPartial

  test "telemetria raccolta ma non normalizzata -> partial":
    let e = newCoverageEntry("X", "segnale grezzo",
                              telemetryCollected = true, normalizedBySiem = false,
                              applicableRuleId = "", detectionFired = false)
    check e.visibility == vlPartial

  test "nessuna telemetria, nessuna normalizzazione -> none":
    let e = newCoverageEntry("X", "comportamento non osservato",
                              telemetryCollected = false, normalizedBySiem = false,
                              applicableRuleId = "", detectionFired = false)
    check e.visibility == vlNone

  test "regola applicabile ma detection NON scattata -> non e' full":
    # caso interessante: la regola esiste ma per qualche motivo non ha
    # fatto match (es. soglia non raggiunta) -> non possiamo dire "full"
    let e = newCoverageEntry("X", "segnale sotto soglia",
                              telemetryCollected = true, normalizedBySiem = true,
                              applicableRuleId = "PROC-001", detectionFired = false)
    check e.visibility == vlPartial

suite "buildCoverageMatrix":
  test "riepilogo conta correttamente gli scenari completamente visibili":
    let entries = @[
      newCoverageEntry("A", "sig-a", true, true, "RULE-A", true),   # full
      newCoverageEntry("B", "sig-b", true, true, "", false),        # partial
      newCoverageEntry("C", "sig-c", false, false, "", false),      # none
      newCoverageEntry("D", "sig-d", true, true, "RULE-D", true)    # full
    ]
    let matrix = buildCoverageMatrix(entries)

    check matrix["total_scenarios"].getInt() == 4
    check matrix["fully_visible_count"].getInt() == 2
    check matrix["coverage_matrix"].len == 4

  test "matrice vuota produce riepilogo coerente (zero, non errore)":
    let matrix = buildCoverageMatrix(@[])
    check matrix["total_scenarios"].getInt() == 0
    check matrix["fully_visible_count"].getInt() == 0
    check matrix["coverage_matrix"].len == 0
NIMTESTSIGCOV

echo "==> Scrittura fixture sorgente per test_artifact_analysis (i binari si ricompilano al bisogno)"
cat > purple-team/nim/tests/fixtures/plaintext_sample.nim << 'NIMFIXTUREPLAIN'
proc main() =
  echo "questo binario contiene la stringa uname in chiaro"
main()
NIMFIXTUREPLAIN

cat > purple-team/nim/tests/fixtures/obfuscated_sample.nim << 'NIMFIXTUREOBF'
proc xorDecode(data: seq[uint8], key: uint8): string =
  result = newString(data.len)
  for i, b in data:
    result[i] = char(b xor key)

proc main() =
  let encoded: seq[uint8] = @[0x2F'u8, 0x34'u8, 0x3B'u8, 0x37'u8, 0x3F'u8]
  let decoded = xorDecode(encoded, 0x5A'u8)
  echo "decodificato a runtime: ", decoded

main()
NIMFIXTUREOBF


# ─────────────────────────────────────────────────────────────────────────
# 9. siem/nim_lab_rules.py + siem/correlation_rules.py + relativi test
# ─────────────────────────────────────────────────────────────────────────
#
# nim_lab_rules.py copre la telemetria "source": "nim-agent" (category
# "behavior"), con lo stesso schema di regola di process_rules.py ma
# adattato ai nomi di campo prodotti da behavior_lab.nim/correlation_lab.nim.
#
# correlation_rules.py e' un MOTORE SEPARATO (non innestato in RULES di
# detector.py): valuta sequenze di eventi (fields.events), non singoli
# eventi isolati — le regole di correlazione non devono mai scattare per
# un solo indicatore.

echo "==> Scrittura siem/nim_lab_rules.py"
cat > siem/nim_lab_rules.py << 'PYFILE_NIMRULES'
"""
nim_lab_rules.py — Detection rules per la telemetria generata dal
laboratorio Nim (eventi con "source": "nim-agent").

Stesso principio di siem/process_rules.py (che copre la telemetria del Go
agent), ma adattato allo schema wire prodotto da behavior_lab.nim /
correlation_lab.nim: qui la categoria è "behavior" invece di "process", e
i campi sono process_name/parent_process_name invece di
child_process_name/process_name usati dallo schema del Go agent.

Principio esplicito (dal quadro concordato con l'utente): NESSUNA regola
qui per eventi con category == "transform" o category == "lifecycle". Il
fatto che un dato sia rappresentato in byte, trasformato in modo
reversibile, o che un programma segua un normale ciclo di vita, non
costituisce di per sé un segnale di detection. Questi eventi restano
comunque visibili e normalizzati nel SIEM (osservabilità), ma non generano
alert: creare una detection "perché sì" per ogni tipo di evento
disponibile produce solo rumore e falsi positivi inutili.
"""

SUSPICIOUS_DISCOVERY_UTILS = {"uname", "whoami", "id", "hostname", "ifconfig", "ip", "w", "who"}
EXPECTED_PARENTS = {"bash", "sh", "zsh", "dash", "systemd", "ansible", "ssh"}


def _is_nim_behavior_spawn(event: dict) -> bool:
    return (
        event.get("source") == "nim-agent"
        and event.get("category") == "behavior"
        and event.get("fields", {}).get("action") == "spawn"
        and bool(event.get("fields", {}).get("process_name"))
    )


def _process_name(event: dict) -> str:
    return (event.get("fields", {}).get("process_name") or "").lower()


def _parent_process_name(event: dict) -> str:
    return (event.get("fields", {}).get("parent_process_name") or "").lower()


NIM_LAB_RULES = [
    {
        "id": "NIM-BEHAVIOR-001",
        "name": "Discovery utility (nim-agent) da parent non whitelisted",
        "description": (
            "Equivalente concettuale di PROC-001, per la telemetria prodotta "
            "dal laboratorio Nim: un'utility di discovery di sistema viene "
            "lanciata da un processo il cui parent non è tra quelli attesi."
        ),
        "severity": "HIGH",
        "category": "behavior",
        "mitre": "T1082",
        "match": lambda e: (
            _is_nim_behavior_spawn(e)
            and _process_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_process_name(e) not in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
    {
        "id": "NIM-BEHAVIOR-002",
        "name": "Discovery utility (nim-agent) da parent atteso",
        "description": (
            "Stesso pattern di NIM-BEHAVIOR-001 ma con parent whitelisted: "
            "probabilmente benigno, severità bassa per sola visibilità."
        ),
        "severity": "LOW",
        "category": "behavior",
        "mitre": "T1082",
        "match": lambda e: (
            _is_nim_behavior_spawn(e)
            and _process_name(e) in SUSPICIOUS_DISCOVERY_UTILS
            and _parent_process_name(e) in EXPECTED_PARENTS
        ),
        "threshold": None,
    },
]
PYFILE_NIMRULES

echo "==> Scrittura siem/correlation_rules.py"
cat > siem/correlation_rules.py << 'PYFILE_CORRRULES'
"""
correlation_rules.py — Motore di correlazione separato per sequenze di
eventi (source == "nim-agent", category == "correlation").

A differenza di process_rules.py e nim_lab_rules.py, che valutano UN
evento alla volta (match(event) -> bool), qui le regole valutano una
SEQUENZA di eventi correlati, incapsulata nel campo "fields.events" di un
evento con category == "correlation" prodotto da correlation_lab.nim.

Motore intenzionalmente separato (non innestato in RULES di detector.py):
la firma di match è diversa (guarda dentro una sequenza annidata, non
i campi di un evento piatto), e le regole di correlazione non devono MAI
scattare per un singolo indicatore isolato — solo per una combinazione di
eventi con una relazione riconoscibile (stessa catena di processo,
sequenza temporale coerente entro una finestra massima).
"""

MAX_CORRELATION_WINDOW_MS = 1000

DISCOVERY_UTILS = {"uname", "whoami", "id", "hostname", "ifconfig", "ip", "w", "who"}


def _is_correlation_event(event: dict) -> bool:
    events = event.get("fields", {}).get("events")
    return event.get("category") == "correlation" and isinstance(events, list)


def _sub_events(event: dict) -> list:
    return event.get("fields", {}).get("events", [])


def _unknown_parent_then_discovery(event: dict) -> bool:
    """
    Condizione CORR-001: un evento A (spawn con parent sconosciuto) seguito,
    entro MAX_CORRELATION_WINDOW_MS, da un evento B in cui il processo
    lanciato da A esegue un'utility di discovery. Nessuno dei due eventi
    preso da solo è necessariamente anomalo — il segnale nasce dalla
    sequenza e dalla coerenza temporale tra i due.
    """
    if not _is_correlation_event(event):
        return False

    subs = _sub_events(event)
    if len(subs) < 2:
        return False

    for i in range(len(subs) - 1):
        a, b = subs[i], subs[i + 1]
        a_fields = a.get("fields", {})
        b_fields = b.get("fields", {})

        a_is_unknown_parent_spawn = (
            a_fields.get("action") == "spawn"
            and a_fields.get("parent_process_name") == "unknown"
        )
        b_is_discovery_child_of_a = (
            b_fields.get("action") == "spawn"
            and b_fields.get("parent_process_name") == a_fields.get("process_name")
            and (b_fields.get("process_name") or "").lower() in DISCOVERY_UTILS
        )
        offset_a = a.get("timestamp_offset_ms", 0)
        offset_b = b.get("timestamp_offset_ms", 0)
        within_window = (offset_b - offset_a) <= MAX_CORRELATION_WINDOW_MS

        if a_is_unknown_parent_spawn and b_is_discovery_child_of_a and within_window:
            return True

    return False


CORRELATION_RULES = [
    {
        "id": "CORR-001",
        "name": "Discovery di sistema dopo processo con parent sconosciuto",
        "description": (
            "Un processo con parent non identificato genera, entro una "
            "finestra temporale ristretta, un processo figlio che esegue "
            "un'utility di discovery di sistema. Il segnale nasce dalla "
            "sequenza e dalla coerenza temporale, non da un singolo evento."
        ),
        "severity": "MEDIUM",
        "category": "correlation",
        "mitre": "T1082",
        "match": _unknown_parent_then_discovery,
        "threshold": None,
    },
]


def evaluate_correlation(event: dict) -> list[str]:
    """Punto di ingresso del motore: quali regole di correlazione scattano
    per questo evento (tipicamente un evento category == "correlation")."""
    return [rule["id"] for rule in CORRELATION_RULES if rule["match"](event)]
PYFILE_CORRRULES

echo "==> Scrittura tests/test_nim_lab_rules.py"
cat > tests/test_nim_lab_rules.py << 'PYFILE_TESTNIMRULES'
from siem.nim_lab_rules import NIM_LAB_RULES


def _fire(event: dict) -> list[str]:
    fired = []
    for rule in NIM_LAB_RULES:
        if rule["match"](event) and (rule["threshold"] is None or rule["threshold"](event)):
            fired.append(rule["id"])
    return fired


def _nim_behavior_event(process_name: str, parent_process_name: str) -> dict:
    return {
        "source": "nim-agent",
        "category": "behavior",
        "fields": {
            "action": "spawn",
            "process_name": process_name,
            "parent_process_name": parent_process_name,
        },
    }


def test_unwhitelisted_parent_triggers_high_severity():
    event = _nim_behavior_event("uname", "loader_test")
    assert _fire(event) == ["NIM-BEHAVIOR-001"]


def test_expected_parent_triggers_only_low_severity():
    event = _nim_behavior_event("uname", "bash")
    assert _fire(event) == ["NIM-BEHAVIOR-002"]


def test_go_agent_process_events_are_not_matched_by_nim_rules():
    # Stesso pattern comportamentale ma source="go-agent": le regole Nim
    # non devono interferire con la telemetria del Go agent (quella la
    # copre process_rules.py).
    event = {
        "source": "go-agent",
        "category": "process",
        "fields": {"action": "spawn", "child_process_name": "uname",
                   "process_name": "loader_test"},
    }
    assert _fire(event) == []


def test_transform_category_never_fires_any_nim_rule():
    # Principio esplicito: nessuna detection per eventi transform/lifecycle.
    event = {
        "source": "nim-agent",
        "category": "transform",
        "fields": {"reversible": True, "key": 90},
    }
    assert _fire(event) == []


def test_lifecycle_category_never_fires_any_nim_rule():
    event = {
        "source": "nim-agent",
        "category": "lifecycle",
        "fields": {"stage": "execution", "sequence_number": 3},
    }
    assert _fire(event) == []


def test_benign_child_process_does_not_trigger():
    event = _nim_behavior_event("ls", "loader_test")
    assert _fire(event) == []


def test_missing_process_name_does_not_trigger():
    event = {
        "source": "nim-agent",
        "category": "behavior",
        "fields": {"action": "spawn", "parent_process_name": "bash"},
    }
    assert _fire(event) == []
PYFILE_TESTNIMRULES

echo "==> Scrittura tests/test_correlation_rules.py"
cat > tests/test_correlation_rules.py << 'PYFILE_TESTCORRRULES'
from siem.correlation_rules import evaluate_correlation, CORRELATION_RULES


def _correlation_event(sub_events: list) -> dict:
    return {
        "source": "nim-agent",
        "category": "correlation",
        "fields": {
            "sequence_id": "CORR-TEST",
            "event_count": len(sub_events),
            "events": sub_events,
        },
    }


def _sub_event(event_id: str, offset_ms: int, action: str,
               process_name: str, parent_process_name: str) -> dict:
    return {
        "event_id": event_id,
        "timestamp_offset_ms": offset_ms,
        "category": "behavior",
        "fields": {
            "action": action,
            "process_name": process_name,
            "parent_process_name": parent_process_name,
        },
    }


def test_positive_sequence_fires_corr_001():
    # Stessa identica forma prodotta da
    # correlation_lab.buildDiscoveryAfterUnexpectedParentSequence()
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "loader_test", "unknown"),
        _sub_event("evt-002", 150, "spawn", "uname", "loader_test"),
    ])
    assert evaluate_correlation(event) == ["CORR-001"]


def test_sequence_outside_time_window_does_not_fire():
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "loader_test", "unknown"),
        _sub_event("evt-002", 5000, "spawn", "uname", "loader_test"),  # troppo tardi
    ])
    assert evaluate_correlation(event) == []


def test_single_event_never_fires_correlation_rule():
    # Un singolo evento isolato, per quanto sospetto, non deve MAI far
    # scattare una regola di correlazione: serve la sequenza.
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "uname", "loader_test"),
    ])
    assert evaluate_correlation(event) == []


def test_known_parent_does_not_fire():
    # Il primo evento ha un parent noto (non "unknown"): non e' il pattern
    # cercato, anche se il secondo evento e' comunque una discovery utility.
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "some_tool", "bash"),
        _sub_event("evt-002", 100, "spawn", "uname", "some_tool"),
    ])
    assert evaluate_correlation(event) == []


def test_second_event_not_a_discovery_util_does_not_fire():
    event = _correlation_event([
        _sub_event("evt-001", 0, "spawn", "loader_test", "unknown"),
        _sub_event("evt-002", 100, "spawn", "ls", "loader_test"),  # non e' discovery
    ])
    assert evaluate_correlation(event) == []


def test_non_correlation_category_is_ignored():
    event = {"source": "nim-agent", "category": "behavior", "fields": {}}
    assert evaluate_correlation(event) == []


def test_empty_sub_events_list_does_not_fire():
    event = _correlation_event([])
    assert evaluate_correlation(event) == []


def test_correlation_rules_have_required_documentation_fields():
    # Ogni regola di correlazione deve documentare id/descrizione/severita'/
    # test positivo-negativo (qui verifichiamo solo la struttura del dict,
    # i test positivo/negativo sono le funzioni sopra).
    for rule in CORRELATION_RULES:
        assert rule["id"]
        assert rule["description"]
        assert rule["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        assert callable(rule["match"])
PYFILE_TESTCORRRULES

# ─────────────────────────────────────────────────────────────────────────
# 10. Patch idempotente di siem/detector.py — aggiunta NIM_LAB_RULES
# ─────────────────────────────────────────────────────────────────────────
#
# Solo NIM_LAB_RULES viene innestato in RULES (stesso meccanismo già usato
# per PROCESS_RULES). CORRELATION_RULES resta deliberatamente FUORI da
# RULES: è un motore separato con firma diversa (valuta sequenze, non
# singoli eventi) — chi consuma la detection lo richiama esplicitamente
# via siem.correlation_rules.evaluate_correlation(event), non tramite il
# loop "for rule in RULES" usato per le regole per-evento.

echo "==> Patch siem/detector.py — aggiunta NIM_LAB_RULES"
python3 - << 'PYEOF'
path = "siem/detector.py"
with open(path) as f:
    content = f.read()

changed = False

if "from siem.nim_lab_rules import NIM_LAB_RULES" not in content:
    anchor = "from siem.process_rules import PROCESS_RULES"
    if anchor not in content:
        print("  ATTENZIONE: ancora import PROCESS_RULES non trovata, import NIM_LAB_RULES non aggiunto — inseriscilo a mano")
    else:
        content = content.replace(
            anchor, anchor + "\nfrom siem.nim_lab_rules import NIM_LAB_RULES"
        )
        changed = True
        print("  -> import NIM_LAB_RULES aggiunto")
else:
    print("  -> import NIM_LAB_RULES già presente, skip")

if "RULES.extend(NIM_LAB_RULES)" not in content:
    anchor = "RULES.extend(PROCESS_RULES)"
    if anchor not in content:
        print("  ATTENZIONE: ancora RULES.extend(PROCESS_RULES) non trovata, riga non aggiunta — inseriscila a mano")
    else:
        content = content.replace(
            anchor, anchor + "\nRULES.extend(NIM_LAB_RULES)"
        )
        changed = True
        print("  -> RULES.extend(NIM_LAB_RULES) aggiunto")
else:
    print("  -> RULES.extend(NIM_LAB_RULES) già presente, skip")

if changed:
    with open(path, "w") as f:
        f.write(content)
PYEOF

# ─────────────────────────────────────────────────────────────────────────
# 11. Patch idempotente del workflow CI — nuovo job nim-purple-team-lab
# ─────────────────────────────────────────────────────────────────────────
#
# Job separato dal 'purple-team-lab' esistente (che resta invariato e
# continua a coprire solo purple-team/nim-loaders/loader.nim). Questo nuovo
# job copre l'intero progetto Nim strutturato in purple-team/nim/:
#   1. installa Nim
#   2. installa le dipendenze tramite Nimble (nessuna esterna oggi, oltre
#      alla libreria standard — il passo resta comunque predisposto per
#      quando in futuro se ne aggiungessero)
#   3. compila il progetto (nimble build)
#   4. esegue l'intera suite di test (nimble test)
#   5. verifica il comportamento previsto (asserzioni nei test stessi)
#   6. esegue un test di integrazione reale con un mock ingress SIEM
#      (round-trip HTTP vero: main --send -> mock ingress)
#   7. esegue i test Python delle nuove regole di detection (nim_lab_rules,
#      correlation_rules), cosi' un fallimento in una qualsiasi delle due
#      metà (Nim o Python) del laboratorio fa fallire chiaramente la CI

if [ -n "$WORKFLOW_FILE" ] && [ -f "$WORKFLOW_FILE" ]; then
  echo "==> Patch $WORKFLOW_FILE — aggiunta job nim-purple-team-lab"
  python3 - "$WORKFLOW_FILE" << 'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

if "nim-purple-team-lab:" in content:
    print("  -> job nim-purple-team-lab già presente, skip")
else:
    job_block = '''  nim-purple-team-lab:
    name: "Nim Purple Team Lab — Build, Test & Integrazione SIEM"
    runs-on: ubuntu-latest
    steps:
      - name: Checkout codice
        uses: actions/checkout@v4

      - name: Installa Nim
        run: |
          sudo apt-get update -qq
          sudo apt-get install -y nim

      - name: Verifica versioni Nim/Nimble
        run: |
          nim --version
          nimble --version

      - name: Nimble install (dipendenze)
        working-directory: purple-team/nim
        run: nimble install -y --depsOnly

      - name: Nimble build
        working-directory: purple-team/nim
        run: nimble build -y

      - name: Nimble test (intera suite, ricompila anche i fixture binari)
        working-directory: purple-team/nim
        run: nimble test -y

      - name: Avvia mock ingress SIEM per il test di integrazione
        working-directory: purple-team/nim
        run: |
          cat > /tmp/mock_ingress.py << 'MOCKEOF'
          import http.server, json

          class Handler(http.server.BaseHTTPRequestHandler):
              def do_POST(self):
                  length = int(self.headers.get("Content-Length", 0))
                  body = self.rfile.read(length)
                  json.loads(body)  # fallisce con eccezione se il JSON e' malformato
                  self.send_response(200)
                  self.send_header("Content-Type", "application/json")
                  self.end_headers()
                  self.wfile.write(b'"'"'{"status":"ok"}'"'"')

              def log_message(self, *args):
                  pass

          http.server.HTTPServer(("127.0.0.1", 5000), Handler).serve_forever()
          MOCKEOF
          nohup python3 /tmp/mock_ingress.py > /tmp/mock_ingress.log 2>&1 &
          sleep 1

      - name: "Round-trip reale: main --send -> mock ingress SIEM"
        working-directory: purple-team/nim
        env:
          SIEM_INGEST_URL: "http://127.0.0.1:5000/api/v1/ingress"
          SIEM_AGENT_TOKEN: "ci-test-token"
        run: ./main --send

      - name: Test Python delle regole di detection per la telemetria Nim
        run: |
          pip install --break-system-packages -q pytest
          pytest tests/test_nim_lab_rules.py tests/test_correlation_rules.py -v

'''
    anchor = "  build-push:\n"
    if anchor not in content:
        print("  ATTENZIONE: ancora 'build-push:' non trovata, job non inserito — incollalo a mano")
    else:
        content = content.replace(anchor, job_block + anchor, 1)
        with open(path, "w") as f:
            f.write(content)
        print("  -> job nim-purple-team-lab inserito prima di build-push")
PYEOF
fi

# ─────────────────────────────────────────────────────────────────────────
# 12. Patch idempotente di ci.yml — aggiunta trigger pull_request
# ─────────────────────────────────────────────────────────────────────────
#
# Senza questo, il job "ci" (e i job purple-team-lab / release-agent-binaries
# appena aggiunti) girano SOLO su push a main/tag — quindi le PR di Dependabot
# non vengono testate prima del merge, e l'auto-merge non ha nessun segnale
# reale su cui basarsi.

if [ -n "$WORKFLOW_FILE" ] && [ -f "$WORKFLOW_FILE" ]; then
  echo "==> Patch $WORKFLOW_FILE — aggiunta trigger pull_request"
  python3 - "$WORKFLOW_FILE" << 'PYEOF'
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

if "pull_request:" in content:
    print("  -> trigger pull_request già presente, skip")
else:
    anchor = "\nconcurrency:\n"
    if anchor not in content:
        print("  ATTENZIONE: ancora 'concurrency:' non trovata, trigger non aggiunto — inseriscilo a mano sotto 'on:'")
    else:
        addition = "  pull_request:\n    branches:\n      - main\n\nconcurrency:\n"
        content = content.replace(anchor, "\n" + addition, 1)
        with open(path, "w") as f:
            f.write(content)
        print("  -> trigger pull_request aggiunto (branches: main)")
PYEOF
fi

echo ""
echo "==> Integrazione completata."
echo "    Prossimi passi:"
echo "    1. export SIEM_AGENT_TOKEN=<un-token-a-caso>  (altrimenti l'auth resta disabilitata)"
echo "    2. pytest tests/test_process_rules.py tests/test_nim_lab_rules.py tests/test_correlation_rules.py -v"
echo "    3. cd agent && go build ./..."
echo "    4. cd purple-team/nim-loaders && nim c -d:release -o:loader_test loader.nim && ./loader_test"
echo "    5. cd purple-team/nim && nimble build -y && nimble test -y"
echo "    6. rivedi il diff con: git diff app.py siem/detector.py .github/workflows/"
echo "    7. il job 'release-agent-binaries' pubblica binari solo sui tag v*.*.* (softprops/action-gh-release@v3)"
echo "    8. il job 'nim-purple-team-lab' compila/testa purple-team/nim/ e verifica un round-trip reale col SIEM"
