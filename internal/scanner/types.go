package scanner

import (
	"github.com/ErdemSusam23/az-port/internal/models"
)

// Scanner defines the interface for platform-specific port scanning
type Scanner interface {
	// ScanPorts performs a port scan and returns all found entries
	ScanPorts() ([]models.PortEntry, error)
	
	// GetProcessInfo retrieves additional process information for a given PID
	GetProcessInfo(pid int) (processName string, processPath string, user string, err error)
}

// ScanOptions represents options for filtering scan results
type ScanOptions struct {
	Protocol   models.Protocol
	State      models.PortState
	PortMin    int
	PortMax    int
	ProcessName string
	PID        int
}

// MatchOptions checks if a port entry matches the given filter options
func MatchOptions(entry models.PortEntry, opts ScanOptions) bool {
	if opts.Protocol != "" && entry.Protocol != opts.Protocol {
		return false
	}
	if opts.State != "" && entry.State != opts.State {
		return false
	}
	if opts.PortMin > 0 && entry.LocalPort < opts.PortMin {
		return false
	}
	if opts.PortMax > 0 && entry.LocalPort > opts.PortMax {
		return false
	}
	if opts.ProcessName != "" && !containsIgnoreCase(entry.ProcessName, opts.ProcessName) {
		return false
	}
	if opts.PID > 0 && entry.PID != opts.PID {
		return false
	}
	return true
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) && 
		(s == substr || 
		 (len(s) > len(substr) && 
		  (s[:len(substr)] == substr || 
		   s[len(s)-len(substr):] == substr ||
		   containsSubstringIgnoreCase(s, substr))))
}

func containsSubstringIgnoreCase(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalIgnoreCase(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
