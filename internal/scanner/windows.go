//go:build windows
// +build windows

package scanner

import (
	"encoding/csv"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ErdemSusam23/az-port/internal/models"
)

// WindowsScanner implements the Scanner interface for Windows
type WindowsScanner struct{}

type processInfo struct {
	name string
	path string
	user string
}

// NewScanner creates a new platform-specific scanner
func NewScanner() Scanner {
	return &WindowsScanner{}
}

// ScanPorts performs port scanning on Windows using netstat
func (s *WindowsScanner) ScanPorts() ([]models.PortEntry, error) {
	// Use netstat as primary method (faster and more reliable)
	entries, err := s.scanWithNetstat()
	if err != nil {
		return nil, err
	}

	processes, err := s.listProcessesPowerShell()
	if err == nil {
		return s.enrichEntriesWithBulkProcessInfo(entries, processes), nil
	}

	processes, err = s.listProcessesTasklist()
	if err == nil {
		return s.enrichEntriesWithBulkProcessInfo(entries, processes), nil
	}

	return s.enrichEntriesWithProcessInfo(entries, s.GetProcessInfo), nil
}

// scanWithPowerShell uses Get-NetTCPConnection for detailed information
func (s *WindowsScanner) scanWithPowerShell() ([]models.PortEntry, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-NetTCPConnection | Select-Object -Property LocalAddress,LocalPort,OwningProcess,State | Format-List")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("powershell command failed: %w", err)
	}

	return s.parsePowerShellOutput(string(output))
}

// scanWithNetstat uses netstat -ano as fallback
func (s *WindowsScanner) scanWithNetstat() ([]models.PortEntry, error) {
	cmd := exec.Command("netstat", "-ano")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("netstat command failed: %w", err)
	}

	return s.parseNetstatOutput(string(output))
}

// parsePowerShellOutput parses the PowerShell output from Get-NetTCPConnection
func (s *WindowsScanner) parsePowerShellOutput(output string) ([]models.PortEntry, error) {
	var entries []models.PortEntry
	
	// Split by double newline (each entry is separated by blank lines)
	blocks := strings.Split(output, "\r\n\r\n")
	if len(blocks) == 0 {
		blocks = strings.Split(output, "\n\n")
	}
	
	for _, block := range blocks {
		block = strings.TrimSpace(block)
		if block == "" || !strings.Contains(block, "LocalAddress") {
			continue
		}

		entry := models.PortEntry{}
		// Split by single newline to get lines
		lines := strings.Split(block, "\r\n")
		if len(lines) == 1 {
			lines = strings.Split(block, "\n")
		}
		
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Format: "Key : Value"
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}

			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			switch key {
			case "LocalAddress":
				entry.LocalAddress = value
			case "LocalPort":
				if port, err := strconv.Atoi(value); err == nil {
					entry.LocalPort = port
				}
			case "OwningProcess":
				if pid, err := strconv.Atoi(value); err == nil {
					entry.PID = pid
				}
			case "State":
				// Map PowerShell state to our model
				state := mapPowerShellState(value)
				entry.State = state
			}
		}

		if entry.LocalPort > 0 && entry.PID > 0 {
			entry.Protocol = models.TCP
			// Get process info
			if name, path, user, err := s.GetProcessInfo(entry.PID); err == nil {
				entry.ProcessName = name
				entry.ProcessPath = path
				entry.User = user
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// mapPowerShellState maps PowerShell state strings to our model
func mapPowerShellState(state string) models.PortState {
	switch strings.ToLower(state) {
	case "listen":
		return models.Listening
	case "established":
		return models.Established
	case "timewait":
		return models.TimeWait
	case "closewait":
		return models.CloseWait
	case "synsent":
		return models.SynSent
	case "synreceived":
		return models.SynReceived
	case "finwait1":
		return models.FinWait1
	case "finwait2":
		return models.FinWait2
	case "closing":
		return models.Closing
	case "lastack":
		return models.LastAck
	default:
		return models.PortState(strings.ToUpper(state))
	}
}

// parseNetstatOutput parses netstat -ano output
func (s *WindowsScanner) parseNetstatOutput(output string) ([]models.PortEntry, error) {
	var entries []models.PortEntry
	
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Active") || strings.HasPrefix(line, "Proto") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		protocol := models.Protocol(strings.ToUpper(fields[0]))
		if protocol != models.TCP && protocol != models.UDP {
			continue
		}

		localAddr := fields[1]
		state := models.Listening
		pidIndex := 0

		switch protocol {
		case models.TCP:
			if len(fields) < 5 {
				continue
			}
			state = models.PortState(fields[3])
			pidIndex = 4
		case models.UDP:
			pidIndex = 3
		}

		// Parse address and port
		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) < 2 {
			continue
		}

		portStr := addrParts[len(addrParts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		pid, err := strconv.Atoi(fields[pidIndex])
		if err != nil {
			continue
		}

		entry := models.PortEntry{
			Protocol:     protocol,
			LocalAddress: localAddr,
			LocalPort:    port,
			State:        state,
			PID:          pid,
			ProcessName:  "N/A", // Will be filled later if needed
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func (s *WindowsScanner) enrichEntriesWithProcessInfo(
	entries []models.PortEntry,
	lookup func(pid int) (string, string, string, error),
) []models.PortEntry {
	cache := make(map[int]processInfo)
	failed := make(map[int]struct{})

	for i := range entries {
		if entries[i].PID <= 0 {
			continue
		}
		if info, ok := cache[entries[i].PID]; ok {
			entries[i].ProcessName = info.name
			entries[i].ProcessPath = info.path
			entries[i].User = info.user
			continue
		}
		if _, ok := failed[entries[i].PID]; ok {
			continue
		}

		name, path, user, err := lookup(entries[i].PID)
		if err != nil {
			failed[entries[i].PID] = struct{}{}
			continue
		}

		info := processInfo{name: name, path: path, user: user}
		cache[entries[i].PID] = info
		entries[i].ProcessName = info.name
		entries[i].ProcessPath = info.path
		entries[i].User = info.user
	}

	return entries
}

func (s *WindowsScanner) listProcessesTasklist() (map[int]processInfo, error) {
	cmd := exec.Command("tasklist", "/FO", "CSV", "/NH")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return s.parseTasklistOutput(string(output))
}

func (s *WindowsScanner) listProcessesPowerShell() (map[int]processInfo, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-Process | Select-Object Id,ProcessName | ConvertTo-Csv -NoTypeInformation")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	return s.parsePowerShellProcessListOutput(string(output))
}

func (s *WindowsScanner) parseTasklistOutput(output string) (map[int]processInfo, error) {
	reader := csv.NewReader(strings.NewReader(output))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	processes := make(map[int]processInfo)

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if len(record) < 2 {
			continue
		}

		pid, err := strconv.Atoi(strings.TrimSpace(record[1]))
		if err != nil {
			continue
		}

		processes[pid] = processInfo{
			name: strings.TrimSpace(record[0]),
		}
	}

	return processes, nil
}

func (s *WindowsScanner) parsePowerShellProcessListOutput(output string) (map[int]processInfo, error) {
	reader := csv.NewReader(strings.NewReader(output))
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	processes := make(map[int]processInfo)

	for {
		record, err := reader.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if len(record) < 2 {
			continue
		}

		if strings.EqualFold(strings.TrimSpace(record[0]), "Id") {
			continue
		}

		pid, err := strconv.Atoi(strings.TrimSpace(record[0]))
		if err != nil {
			continue
		}

		name := strings.TrimSpace(record[1])
		if name == "" {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".exe") {
			name += ".exe"
		}

		processes[pid] = processInfo{name: name}
	}

	return processes, nil
}

func (s *WindowsScanner) enrichEntriesWithBulkProcessInfo(
	entries []models.PortEntry,
	processes map[int]processInfo,
) []models.PortEntry {
	for i := range entries {
		if entries[i].PID <= 0 {
			continue
		}
		info, ok := processes[entries[i].PID]
		if !ok {
			continue
		}
		entries[i].ProcessName = info.name
		if entries[i].ProcessPath == "" {
			entries[i].ProcessPath = info.path
		}
		if entries[i].User == "" {
			entries[i].User = info.user
		}
	}

	return entries
}

// GetProcessInfo retrieves process information for a given PID
func (s *WindowsScanner) GetProcessInfo(pid int) (string, string, string, error) {
	// Try PowerShell first
	name, path, user, err := s.getProcessInfoPowerShell(pid)
	if err == nil {
		return name, path, user, nil
	}

	// Fallback to tasklist
	return s.getProcessInfoTasklist(pid)
}

func (s *WindowsScanner) getProcessInfoPowerShell(pid int) (string, string, string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("Get-Process -Id %d | Select-Object -Property Name,Path,StartInfo | Format-List", pid))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", "", err
	}

	lines := strings.Split(string(output), "\n")
	name := ""
	path := ""
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				name = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "Path") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				path = strings.TrimSpace(parts[1])
			}
		}
	}

	if name == "" {
		return "", "", "", fmt.Errorf("process not found")
	}

	// Get user (requires admin for full info)
	user, _ := s.getProcessUserPowerShell(pid)

	return name + ".exe", path, user, nil
}

func (s *WindowsScanner) getProcessUserPowerShell(pid int) (string, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf("(Get-CimInstance Win32_Process -Filter \"ProcessId=%d\").GetOwner().User", pid))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

func (s *WindowsScanner) getProcessInfoTasklist(pid int) (string, string, string, error) {
	cmd := exec.Command("tasklist", "/FI", fmt.Sprintf("PID eq %d", pid), "/FO", "CSV", "/NH")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", "", err
	}

	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		return "", "", "", fmt.Errorf("no process found")
	}

	// Parse CSV: "Image Name","PID","Session Name","Session#","Mem Usage"
	line := strings.TrimSpace(lines[0])
	if line == "" {
		return "", "", "", fmt.Errorf("no process found")
	}

	fields := strings.Split(line, ",")
	if len(fields) < 2 {
		return "", "", "", fmt.Errorf("unexpected format")
	}

	name := strings.Trim(fields[0], "\"")
	return name, "", "", nil
}
