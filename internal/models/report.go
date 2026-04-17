package models

// ConflictKind describes how multiple entries on the same port should be interpreted.
type ConflictKind string

const (
	NoConflictKind     ConflictKind = "NONE"
	SharedProcessKind  ConflictKind = "SHARED_PROCESS"
	RealConflictKind   ConflictKind = "REAL_CONFLICT"
)

// ConflictReport represents a port conflict analysis result
type ConflictReport struct {
	Port        int
	Entries     []PortEntry
	HasConflict bool
	Kind        ConflictKind
	RiskLevel   RiskLevel
}

// PortStatus is the normalized result state for a port-oriented command.
type PortStatus string

const (
	PortStatusAvailable     PortStatus = "available"
	PortStatusInUse         PortStatus = "in_use"
	PortStatusSharedProcess PortStatus = "shared_process"
	PortStatusRealConflict  PortStatus = "real_conflict"
	PortStatusSuggested     PortStatus = "suggested"
)

// ProcessRef is a lightweight process representation for reports.
type ProcessRef struct {
	PID       int      `json:"pid"`
	Name      string   `json:"name"`
	Addresses []string `json:"addresses,omitempty"`
}

// PortFinding is a structured finding emitted by check/find/conflicts/suggest commands.
type PortFinding struct {
	Port      int          `json:"port"`
	Status    PortStatus   `json:"status"`
	RiskLevel RiskLevel    `json:"risk_level,omitempty"`
	Message   string       `json:"message,omitempty"`
	Processes []ProcessRef `json:"processes,omitempty"`
}

// CommandMetrics summarizes execution health and usefulness for a command.
type CommandMetrics struct {
	DurationMs            int64   `json:"duration_ms"`
	EntriesScanned        int     `json:"entries_scanned"`
	FindingsCount         int     `json:"findings_count"`
	ProcessResolutionRate float64 `json:"process_resolution_rate"`
}

// CommandReport is the structured machine-readable output for a command.
type CommandReport struct {
	Command         string         `json:"command"`
	Summary         string         `json:"summary"`
	Findings        []PortFinding  `json:"findings,omitempty"`
	Recommendations []string       `json:"recommendations,omitempty"`
	Metrics         CommandMetrics `json:"metrics"`
}

// ScanResult represents the result of a port scan
type ScanResult struct {
	Entries   []PortEntry
	TotalCount int
	Error     error
}
