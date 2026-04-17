package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppendLocalEventCreatesJSONLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metrics", "events.jsonl")
	event := Event{
		Timestamp:             time.Date(2026, 4, 17, 12, 0, 0, 0, time.UTC),
		Command:               "check",
		DurationMs:            125,
		EntriesScanned:        42,
		FindingsCount:         2,
		ProcessResolutionRate: 0.95,
	}

	if err := AppendLocalEvent(path, event); err != nil {
		t.Fatalf("AppendLocalEvent returned error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, `"command":"check"`) {
		t.Fatalf("expected command field in log line, got %q", content)
	}
	if !strings.Contains(content, `"duration_ms":125`) {
		t.Fatalf("expected duration field in log line, got %q", content)
	}
}
