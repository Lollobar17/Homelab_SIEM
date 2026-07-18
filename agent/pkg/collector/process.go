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
