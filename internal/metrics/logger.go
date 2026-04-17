package metrics

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Event is a local-first metrics record emitted per command execution.
type Event struct {
	Timestamp             time.Time `json:"timestamp"`
	Command               string    `json:"command"`
	DurationMs            int64     `json:"duration_ms"`
	EntriesScanned        int       `json:"entries_scanned"`
	FindingsCount         int       `json:"findings_count"`
	ProcessResolutionRate float64   `json:"process_resolution_rate"`
}

// AppendLocalEvent appends one JSON line to a local metrics file.
func AppendLocalEvent(path string, event Event) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if _, err := file.Write(append(data, '\n')); err != nil {
		return err
	}

	return nil
}
