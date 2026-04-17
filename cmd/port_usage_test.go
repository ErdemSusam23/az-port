package cmd

import (
	"strings"
	"testing"

	"github.com/ErdemSusam23/az-port/internal/models"
)

func TestSummarizePortEntriesMergesSameProcessAcrossAddresses(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "postgres.exe"},
		{Protocol: models.TCP, LocalAddress: "[::]:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "postgres.exe"},
	}

	summaries := summarizePortEntries(entries)
	if len(summaries) != 1 {
		t.Fatalf("expected one merged summary, got %d", len(summaries))
	}
	if len(summaries[0].Addresses) != 2 {
		t.Fatalf("expected both addresses to be preserved, got %+v", summaries[0])
	}
}

func TestBuildPortStatusMessageForSharedProcess(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "postgres.exe"},
		{Protocol: models.TCP, LocalAddress: "[::]:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "postgres.exe"},
	}
	report := &models.ConflictReport{
		Port:        5432,
		Entries:     entries,
		HasConflict: false,
		Kind:        models.SharedProcessKind,
		RiskLevel:   models.Low,
	}

	message := buildPortStatusMessage(5432, entries, report)
	if !strings.Contains(message, "No real conflict") {
		t.Fatalf("expected shared-process status to say no real conflict, got %q", message)
	}
	if !strings.Contains(message, "postgres.exe (PID: 6280)") {
		t.Fatalf("expected process summary in message, got %q", message)
	}
	if !strings.Contains(message, "0.0.0.0:5432") || !strings.Contains(message, "[::]:5432") {
		t.Fatalf("expected both addresses in message, got %q", message)
	}
}

func TestBuildPortStatusMessageForRealConflict(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:3000", LocalPort: 3000, State: models.Listening, PID: 1234, ProcessName: "node.exe"},
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:3000", LocalPort: 3000, State: models.Listening, PID: 5678, ProcessName: "java.exe"},
	}
	report := &models.ConflictReport{
		Port:        3000,
		Entries:     entries,
		HasConflict: true,
		Kind:        models.RealConflictKind,
		RiskLevel:   models.High,
	}

	message := buildPortStatusMessage(3000, entries, report)
	if !strings.Contains(message, "REAL CONFLICT") {
		t.Fatalf("expected real conflict marker, got %q", message)
	}
	if !strings.Contains(message, "node.exe (PID: 1234)") || !strings.Contains(message, "java.exe (PID: 5678)") {
		t.Fatalf("expected both processes in message, got %q", message)
	}
}
