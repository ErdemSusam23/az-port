package analyzer

import (
	"testing"

	"github.com/ErdemSusam23/az-port/internal/models"
)

func TestGetConflictsOnlyIgnoresDualStackEntriesFromSameProcess(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "postgres.exe"},
		{Protocol: models.TCP, LocalAddress: "[::]:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "postgres.exe"},
	}

	conflicts := GetConflictsOnly(entries)
	if len(conflicts) != 0 {
		t.Fatalf("expected no conflicts for same-process dual-stack listeners, got %+v", conflicts)
	}
}

func TestGetConflictsOnlyReportsDifferentListeningProcesses(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:3000", LocalPort: 3000, State: models.Listening, PID: 1234, ProcessName: "node.exe"},
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:3000", LocalPort: 3000, State: models.Listening, PID: 5678, ProcessName: "java.exe"},
	}

	conflicts := GetConflictsOnly(entries)
	if len(conflicts) != 1 {
		t.Fatalf("expected one real conflict, got %d", len(conflicts))
	}
	if !conflicts[0].HasConflict {
		t.Fatalf("expected conflict report to be marked as real conflict, got %+v", conflicts[0])
	}
}

func TestGetConflictsOnlyIgnoresConnectionNoise(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:5037", LocalPort: 5037, State: models.Listening, PID: 6808, ProcessName: "adb.exe"},
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:5037", LocalPort: 5037, State: models.Established, PID: 6808, ProcessName: "adb.exe"},
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:5037", LocalPort: 5037, State: models.TimeWait, PID: 0, ProcessName: "N/A"},
	}

	conflicts := GetConflictsOnly(entries)
	if len(conflicts) != 0 {
		t.Fatalf("expected connection states to be ignored in conflict detection, got %+v", conflicts)
	}
}
