package cmd

import (
	"fmt"
	"strings"

	"github.com/ErdemSusam23/az-port/internal/models"
)

type portProcessSummary struct {
	PID         int
	ProcessName string
	ProcessPath string
	User        string
	Addresses   []string
	Protocols   []models.Protocol
	States      []models.PortState
}

func filterPortUsageEntries(entries []models.PortEntry, port int) []models.PortEntry {
	var filtered []models.PortEntry
	for _, entry := range entries {
		if entry.LocalPort != port {
			continue
		}
		if !isPortUsageEntry(entry) {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func isPortUsageEntry(entry models.PortEntry) bool {
	if entry.PID <= 0 {
		return false
	}
	if entry.Protocol == models.UDP {
		return true
	}
	return entry.State == models.Listening
}

func summarizePortEntries(entries []models.PortEntry) []portProcessSummary {
	var summaries []portProcessSummary
	indexByPID := make(map[int]int)

	for _, entry := range entries {
		idx, ok := indexByPID[entry.PID]
		if !ok {
			summaries = append(summaries, portProcessSummary{
				PID:         entry.PID,
				ProcessName: entry.ProcessName,
				ProcessPath: entry.ProcessPath,
				User:        entry.User,
				Addresses:   []string{entry.LocalAddress},
				Protocols:   []models.Protocol{entry.Protocol},
				States:      []models.PortState{entry.State},
			})
			indexByPID[entry.PID] = len(summaries) - 1
			continue
		}

		summaries[idx].Addresses = appendUniqueString(summaries[idx].Addresses, entry.LocalAddress)
		summaries[idx].Protocols = appendUniqueProtocol(summaries[idx].Protocols, entry.Protocol)
		summaries[idx].States = appendUniqueState(summaries[idx].States, entry.State)
		if summaries[idx].ProcessPath == "" {
			summaries[idx].ProcessPath = entry.ProcessPath
		}
		if summaries[idx].User == "" {
			summaries[idx].User = entry.User
		}
		if summaries[idx].ProcessName == "" || summaries[idx].ProcessName == "N/A" {
			summaries[idx].ProcessName = entry.ProcessName
		}
	}

	return summaries
}

func buildPortStatusMessage(port int, entries []models.PortEntry, report *models.ConflictReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Port %d:\n", port)

	if len(entries) == 0 {
		b.WriteString("  Not in use")
		return b.String()
	}

	summaries := summarizePortEntries(entries)
	switch {
	case report != nil && report.Kind == models.RealConflictKind:
		b.WriteString("  REAL CONFLICT\n")
		for _, summary := range summaries {
			fmt.Fprintf(&b, "  - %s (PID: %d)\n", displayProcessName(summary.ProcessName), summary.PID)
			fmt.Fprintf(&b, "    Addresses: %s\n", strings.Join(summary.Addresses, ", "))
		}
	case report != nil && report.Kind == models.CooperativeKind:
		b.WriteString("  Cooperative binding (no real conflict)\n")
		for _, summary := range summaries {
			fmt.Fprintf(&b, "  - %s (PID: %d)\n", displayProcessName(summary.ProcessName), summary.PID)
			fmt.Fprintf(&b, "    Addresses: %s\n", strings.Join(summary.Addresses, ", "))
		}
	case report != nil && report.Kind == models.SharedProcessKind:
		summary := summaries[0]
		fmt.Fprintf(&b, "  In use by %s (PID: %d)\n", displayProcessName(summary.ProcessName), summary.PID)
		b.WriteString("  No real conflict\n")
		fmt.Fprintf(&b, "  Addresses: %s", strings.Join(summary.Addresses, ", "))
	default:
		for i, summary := range summaries {
			if i > 0 {
				b.WriteString("\n")
			}
			fmt.Fprintf(&b, "  In use by %s (PID: %d)\n", displayProcessName(summary.ProcessName), summary.PID)
			fmt.Fprintf(&b, "  Addresses: %s\n", strings.Join(summary.Addresses, ", "))
			if summary.ProcessPath != "" {
				fmt.Fprintf(&b, "  Path: %s\n", summary.ProcessPath)
			}
			if summary.User != "" {
				fmt.Fprintf(&b, "  User: %s\n", summary.User)
			}
		}
	}

	return strings.TrimRight(b.String(), "\n")
}

func displayProcessName(name string) string {
	if strings.TrimSpace(name) == "" {
		return "unknown"
	}
	return name
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueProtocol(values []models.Protocol, value models.Protocol) []models.Protocol {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func appendUniqueState(values []models.PortState, value models.PortState) []models.PortState {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
