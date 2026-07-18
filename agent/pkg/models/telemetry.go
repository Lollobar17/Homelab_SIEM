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
