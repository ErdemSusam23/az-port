//go:build linux || darwin
// +build linux darwin

package scanner

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/ErdemSusam23/az-port/internal/models"
)

// UnixScanner implements the Scanner interface for Linux/macOS
type UnixScanner struct{}

// NewScanner creates a new platform-specific scanner
func NewScanner() Scanner {
	return &UnixScanner{}
}

// ScanPorts performs port scanning on Unix systems using ss or lsof
func (s *UnixScanner) ScanPorts() ([]models.PortEntry, error) {
	// Try ss first (Linux, faster and modern)
	entries, err := s.scanWithSS()
	if err == nil && len(entries) > 0 {
		return entries, nil
	}

	// Fallback to lsof (works on both Linux and macOS)
	return s.scanWithLsof()
}

// scanWithSS uses ss command (Linux)
func (s *UnixScanner) scanWithSS() ([]models.PortEntry, error) {
	cmd := exec.Command("ss", "-tlnp")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("ss command failed: %w", err)
	}

	return s.parseSSOutput(string(output))
}

// scanWithLsof uses lsof command (Linux/macOS)
func (s *UnixScanner) scanWithLsof() ([]models.PortEntry, error) {
	cmd := exec.Command("lsof", "-i", "-P", "-n")
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("lsof command failed: %w", err)
	}

	return s.parseLsofOutput(string(output))
}

// parseSSOutput parses ss -tlnp output
func (s *UnixScanner) parseSSOutput(output string) ([]models.PortEntry, error) {
	var entries []models.PortEntry
	
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "State") || strings.HasPrefix(line, "Netid") {
			continue
		}

		// Example: LISTEN  0  128  0.0.0.0:80  0.0.0.0:*  users:(("nginx",pid=1234,fd=6))
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		state := fields[0]
		localAddr := fields[4]

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

		entry := models.PortEntry{
			Protocol:     models.TCP,
			LocalAddress: localAddr,
			LocalPort:    port,
			State:        models.PortState(state),
		}

		// Try to extract PID and process name from users:(("name",pid=XXX,...))
		if usersIdx := strings.Index(line, "users:"); usersIdx != -1 {
			usersPart := line[usersIdx:]
			if pidStart := strings.Index(usersPart, "pid="); pidStart != -1 {
				pidStart += 4
				pidEnd := strings.Index(usersPart[pidStart:], ",")
				if pidEnd == -1 {
					pidEnd = strings.Index(usersPart[pidStart:], ")")
				}
				if pidEnd != -1 {
					pidStr := usersPart[pidStart : pidStart+pidEnd]
					if pid, err := strconv.Atoi(pidStr); err == nil {
						entry.PID = pid
						// Get process info
						if name, path, user, err := s.GetProcessInfo(pid); err == nil {
							entry.ProcessName = name
							entry.ProcessPath = path
							entry.User = user
						}
					}
				}
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// parseLsofOutput parses lsof -i -P -n output
func (s *UnixScanner) parseLsofOutput(output string) ([]models.PortEntry, error) {
	var entries []models.PortEntry
	
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "COMMAND") {
			continue
		}

		// Example: nginx  1234  root  6u  IPv4  12345  0t0  TCP *:80 (LISTEN)
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		commandName := fields[0]
		pidStr := fields[1]
		user := fields[2]
		
		// Parse PID
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}

		// Parse protocol and address
		// fields[7] = TCP/UDP, fields[8] = address:port or *:port
		protocol := models.Protocol(fields[7])
		if protocol != models.TCP && protocol != models.UDP {
			continue
		}

		localAddr := fields[8]
		
		// Extract port from address
		addrParts := strings.Split(localAddr, ":")
		if len(addrParts) < 2 {
			continue
		}
		portStr := addrParts[len(addrParts)-1]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// Extract state from parentheses
		state := models.Listening
		if idx := strings.Index(line, "(LISTEN)"); idx != -1 {
			state = models.Listening
		} else if idx := strings.Index(line, "(ESTABLISHED)"); idx != -1 {
			state = models.Established
		}

		entry := models.PortEntry{
			Protocol:     protocol,
			LocalAddress: localAddr,
			LocalPort:    port,
			State:        state,
			PID:          pid,
			ProcessName:  commandName,
			User:         user,
		}

		// Get process path
		if path, _, _, err := s.GetProcessInfo(pid); err == nil {
			entry.ProcessPath = path
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// GetProcessInfo retrieves process information for a given PID
func (s *UnixScanner) GetProcessInfo(pid int) (string, string, string, error) {
	// Get process name and path from /proc (Linux) or ps (macOS)
	name, path, err := s.getProcessNameAndPath(pid)
	if err != nil {
		return "", "", "", err
	}

	// Get user
	user, err := s.getProcessUser(pid)
	if err != nil {
		user = "unknown"
	}

	return name, path, user, nil
}

func (s *UnixScanner) getProcessNameAndPath(pid int) (string, string, error) {
	// Try /proc first (Linux)
	cmd := exec.Command("cat", fmt.Sprintf("/proc/%d/cmdline", pid))
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		// cmdline uses null bytes as separators
		cmdline := string(output)
		cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		cmdline = strings.TrimSpace(cmdline)
		if cmdline != "" {
			// Extract just the command name
			parts := strings.Fields(cmdline)
			if len(parts) > 0 {
				name := parts[0]
				// Get basename
				if idx := strings.LastIndex(name, "/"); idx != -1 {
					name = name[idx+1:]
				}
				return name, cmdline, nil
			}
		}
	}

	// Fallback to ps
	cmd = exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=", "-o", "args=")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("process not found")
	}

	line := strings.TrimSpace(string(output))
	if line == "" {
		return "", "", fmt.Errorf("process not found")
	}

	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", fmt.Errorf("process not found")
	}

	name := fields[0]
	path := line

	return name, path, nil
}

func (s *UnixScanner) getProcessUser(pid int) (string, error) {
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "user=")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}
