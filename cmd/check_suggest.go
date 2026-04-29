package cmd

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/ErdemSusam23/az-port/internal/analyzer"
	"github.com/ErdemSusam23/az-port/internal/config"
	"github.com/ErdemSusam23/az-port/internal/models"
)

func resolveCheckPorts(args []int, cfg config.ProjectConfig) ([]int, error) {
	if len(args) > 0 {
		return args, nil
	}
	if len(cfg.ExpectedPorts) > 0 {
		return cfg.ExpectedPorts, nil
	}
	return nil, fmt.Errorf("no ports provided and no expected_ports found in config")
}

func buildCheckReport(entries []models.PortEntry, ports []int, cfg config.ProjectConfig) models.CommandReport {
	report := models.CommandReport{
		Command: "check",
	}

	used := usedPorts(entries)
	for _, port := range ports {
		portEntries := filterPortUsageEntries(entries, port)
		conflict := analyzer.GetConflictsWithPort(portEntries, port)
		report.Findings = append(report.Findings, buildPortFinding(port, portEntries, conflict))
	}

	report.Summary = summarizeFindings(report.Findings)
	report.Metrics.FindingsCount = len(report.Findings)

	if hasUnavailableFindings(report.Findings) {
		suggestRange := cfg.SuggestRange
		if suggestRange == "" {
			suggestRange = "3000-3999"
		}
		count := cfg.SuggestCount
		if count <= 0 {
			count = 3
		}
		suggestions := suggestAvailablePorts(used, suggestRange, count)
		if len(suggestions) > 0 {
			var labels []string
			for _, port := range suggestions {
				labels = append(labels, strconv.Itoa(port))
			}
			report.Recommendations = append(report.Recommendations, fmt.Sprintf("Try available port(s): %s", strings.Join(labels, ", ")))
		}
	}

	return report
}

func buildFindReport(entries []models.PortEntry, ports []int, cfg config.ProjectConfig) models.CommandReport {
	report := buildCheckReport(entries, ports, cfg)
	report.Command = "find"
	return report
}

func buildSuggestReport(entries []models.PortEntry, portRange string, count int) (models.CommandReport, error) {
	if count <= 0 {
		count = 5
	}

	suggestions := suggestAvailablePorts(usedPorts(entries), portRange, count)
	report := models.CommandReport{
		Command: "suggest",
	}

	for _, port := range suggestions {
		report.Findings = append(report.Findings, models.PortFinding{
			Port:    port,
			Status:  models.PortStatusSuggested,
			Message: fmt.Sprintf("Port %d is available", port),
		})
	}

	report.Summary = fmt.Sprintf("%d available port(s) suggested", len(report.Findings))
	report.Metrics.FindingsCount = len(report.Findings)

	if len(report.Findings) == 0 {
		return report, fmt.Errorf("no available ports found in range %s", portRange)
	}

	return report, nil
}

func buildConflictsReport(entries []models.PortEntry) models.CommandReport {
	report := models.CommandReport{Command: "conflicts"}

	for _, conflict := range analyzer.GetConflictsOnly(entries) {
		finding := models.PortFinding{
			Port:      conflict.Port,
			Status:    models.PortStatusRealConflict,
			RiskLevel: conflict.RiskLevel,
			Message:   fmt.Sprintf("Port %d has a real conflict", conflict.Port),
		}
		for _, summary := range summarizePortEntries(conflict.Entries) {
			finding.Processes = append(finding.Processes, models.ProcessRef{
				PID:       summary.PID,
				Name:      displayProcessName(summary.ProcessName),
				Addresses: summary.Addresses,
			})
		}
		report.Findings = append(report.Findings, finding)
	}

	report.Summary = summarizeFindings(report.Findings)
	report.Metrics.FindingsCount = len(report.Findings)
	return report
}

func buildListReport(entries []models.PortEntry) models.CommandReport {
	report := models.CommandReport{
		Command: "list",
		Summary: fmt.Sprintf("%d port entries listed", len(entries)),
	}

	for _, entry := range entries {
		report.Findings = append(report.Findings, models.PortFinding{
			Port:    entry.LocalPort,
			Status:  models.PortStatusInUse,
			Message: fmt.Sprintf("%s %s", entry.Protocol, entry.LocalAddress),
			Processes: []models.ProcessRef{{
				PID:       entry.PID,
				Name:      displayProcessName(entry.ProcessName),
				Addresses: []string{entry.LocalAddress},
			}},
		})
	}

	report.Metrics.FindingsCount = len(report.Findings)
	return report
}

func buildPortFinding(port int, entries []models.PortEntry, conflict *models.ConflictReport) models.PortFinding {
	if len(entries) == 0 {
		return models.PortFinding{
			Port:    port,
			Status:  models.PortStatusAvailable,
			Message: fmt.Sprintf("Port %d is available", port),
		}
	}

	finding := models.PortFinding{
		Port:      port,
		RiskLevel: models.Low,
		Processes: make([]models.ProcessRef, 0, len(entries)),
	}

	for _, summary := range summarizePortEntries(entries) {
		finding.Processes = append(finding.Processes, models.ProcessRef{
			PID:       summary.PID,
			Name:      displayProcessName(summary.ProcessName),
			Addresses: summary.Addresses,
		})
	}

	switch {
	case conflict != nil && conflict.Kind == models.RealConflictKind:
		finding.Status = models.PortStatusRealConflict
		finding.RiskLevel = conflict.RiskLevel
		finding.Message = fmt.Sprintf("Port %d has a real conflict", port)
	case conflict != nil && conflict.Kind == models.CooperativeKind:
		finding.Status = models.PortStatusCooperative
		finding.Message = fmt.Sprintf("Port %d has cooperative bindings (no real conflict)", port)
	case conflict != nil && conflict.Kind == models.SharedProcessKind:
		finding.Status = models.PortStatusSharedProcess
		finding.Message = fmt.Sprintf("Port %d is used by the same process on multiple addresses", port)
	default:
		finding.Status = models.PortStatusInUse
		finding.Message = fmt.Sprintf("Port %d is already in use", port)
	}

	return finding
}

func summarizeFindings(findings []models.PortFinding) string {
	counts := map[models.PortStatus]int{}
	for _, finding := range findings {
		counts[finding.Status]++
	}

	var parts []string
	for _, status := range []models.PortStatus{
		models.PortStatusAvailable,
		models.PortStatusInUse,
		models.PortStatusSharedProcess,
		models.PortStatusCooperative,
		models.PortStatusRealConflict,
		models.PortStatusSuggested,
	} {
		if counts[status] == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d %s", counts[status], status))
	}

	if len(parts) == 0 {
		return "no findings"
	}

	return strings.Join(parts, ", ")
}

func hasUnavailableFindings(findings []models.PortFinding) bool {
	for _, finding := range findings {
		if finding.Status != models.PortStatusAvailable {
			return true
		}
	}
	return false
}

func usedPorts(entries []models.PortEntry) map[int]struct{} {
	used := make(map[int]struct{})
	for _, entry := range entries {
		if entry.PID <= 0 {
			continue
		}
		used[entry.LocalPort] = struct{}{}
	}
	return used
}

func suggestAvailablePorts(used map[int]struct{}, portRange string, count int) []int {
	min, max := parsePortRangeOrDefault(portRange, 3000, 3999)
	var suggestions []int
	for port := min; port <= max && len(suggestions) < count; port++ {
		if _, ok := used[port]; ok {
			continue
		}
		suggestions = append(suggestions, port)
	}
	sort.Ints(suggestions)
	return suggestions
}

func parsePortRangeOrDefault(portRange string, defaultMin, defaultMax int) (int, int) {
	if strings.TrimSpace(portRange) == "" {
		return defaultMin, defaultMax
	}

	var min, max int
	if _, err := fmt.Sscanf(portRange, "%d-%d", &min, &max); err != nil || min < 1 || max > 65535 || min > max {
		return defaultMin, defaultMax
	}
	return min, max
}

func formatHumanReport(report models.CommandReport) string {
	var b strings.Builder
	if report.Summary != "" {
		b.WriteString(report.Summary)
		b.WriteString("\n")
	}

	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "- Port %d: %s", finding.Port, finding.Status)
		if finding.Message != "" {
			fmt.Fprintf(&b, " (%s)", finding.Message)
		}
		b.WriteString("\n")
		for _, process := range finding.Processes {
			fmt.Fprintf(&b, "  %s (PID: %d)", process.Name, process.PID)
			if len(process.Addresses) > 0 {
				fmt.Fprintf(&b, " [%s]", strings.Join(process.Addresses, ", "))
			}
			b.WriteString("\n")
		}
	}

	for _, recommendation := range report.Recommendations {
		fmt.Fprintf(&b, "Recommendation: %s\n", recommendation)
	}

	return strings.TrimRight(b.String(), "\n")
}

func mustGetwd() string {
	wd, err := os.Getwd()
	if err != nil {
		CheckErr(fmt.Errorf("failed to get working directory: %w", err))
	}
	return wd
}
