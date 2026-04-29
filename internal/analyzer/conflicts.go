package analyzer

import (
	"net"

	"github.com/ErdemSusam23/az-port/internal/models"
)

// DetectConflicts analyzes port entries and detects conflicts
func DetectConflicts(entries []models.PortEntry) []models.ConflictReport {
	// Group entries by port
	portMap := make(map[int][]models.PortEntry)
	for _, entry := range entries {
		if !isConflictEligible(entry) {
			continue
		}
		portMap[entry.LocalPort] = append(portMap[entry.LocalPort], entry)
	}

	var reports []models.ConflictReport

	for port, portEntries := range portMap {
		report := models.ConflictReport{
			Port:    port,
			Entries: portEntries,
			Kind:    models.NoConflictKind,
		}

		uniquePIDs := uniquePIDs(portEntries)
		switch {
		case len(uniquePIDs) > 1:
			if hasAddressConflict(portEntries) {
				report.HasConflict = true
				report.Kind = models.RealConflictKind
				report.RiskLevel = calculateRiskLevel(portEntries, port)
			} else {
				report.HasConflict = false
				report.Kind = models.CooperativeKind
				report.RiskLevel = models.Low
			}
		case len(portEntries) > 1:
			report.HasConflict = false
			report.Kind = models.SharedProcessKind
			report.RiskLevel = models.Low
		default:
			report.HasConflict = false
			report.Kind = models.NoConflictKind
			report.RiskLevel = models.Low
		}

		reports = append(reports, report)
	}

	return reports
}

// calculateRiskLevel determines the risk level based on port and process information
func calculateRiskLevel(entries []models.PortEntry, port int) models.RiskLevel {
	// Well-known ports (0-1023) are higher risk
	if port < 1024 {
		return models.High
	}

	// Registered ports (1024-49151) medium risk
	if port < 49152 {
		// Check if different process names
		processNames := make(map[string]bool)
		for _, entry := range entries {
			processNames[entry.ProcessName] = true
		}
		
		if len(processNames) > 1 {
			return models.High // Different processes on same port
		}
		return models.Medium
	}

	// Dynamic/private ports (49152-65535) lower risk
	return models.Medium
}

// GetConflictsWithPort returns conflicts for a specific port
func GetConflictsWithPort(entries []models.PortEntry, port int) *models.ConflictReport {
	reports := DetectConflicts(entries)
	
	for _, report := range reports {
		if report.Port == port {
			return &report
		}
	}
	
	return nil
}

// GetConflictsOnly returns only entries with actual conflicts
func GetConflictsOnly(entries []models.PortEntry) []models.ConflictReport {
	reports := DetectConflicts(entries)
	
	var conflicts []models.ConflictReport
	for _, report := range reports {
		if report.Kind == models.RealConflictKind {
			conflicts = append(conflicts, report)
		}
	}
	
	return conflicts
}

func isConflictEligible(entry models.PortEntry) bool {
	if entry.PID <= 0 {
		return false
	}

	if entry.Protocol == models.UDP {
		return true
	}

	return entry.State == models.Listening
}

func extractIP(localAddress string) net.IP {
	host, _, err := net.SplitHostPort(localAddress)
	if err != nil {
		host = localAddress
	}
	return net.ParseIP(host)
}

func addressesOverlap(addr1, addr2 string) bool {
	ip1 := extractIP(addr1)
	ip2 := extractIP(addr2)
	if ip1 == nil || ip2 == nil {
		return true
	}
	isIPv4_1 := ip1.To4() != nil
	isIPv4_2 := ip2.To4() != nil
	if isIPv4_1 != isIPv4_2 {
		return false
	}
	if ip1.IsUnspecified() && ip2.IsUnspecified() {
		return true
	}
	if ip1.IsUnspecified() || ip2.IsUnspecified() {
		return false
	}
	return ip1.Equal(ip2)
}

func hasAddressConflict(entries []models.PortEntry) bool {
	byPID := make(map[int][]string)
	for _, e := range entries {
		byPID[e.PID] = append(byPID[e.PID], e.LocalAddress)
	}
	pids := make([]int, 0, len(byPID))
	for pid := range byPID {
		pids = append(pids, pid)
	}
	for i := 0; i < len(pids); i++ {
		for j := i + 1; j < len(pids); j++ {
			for _, a := range byPID[pids[i]] {
				for _, b := range byPID[pids[j]] {
					if addressesOverlap(a, b) {
						return true
					}
				}
			}
		}
	}
	return false
}

func uniquePIDs(entries []models.PortEntry) map[int]struct{} {
	unique := make(map[int]struct{})
	for _, entry := range entries {
		unique[entry.PID] = struct{}{}
	}
	return unique
}
