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
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:3000", LocalPort: 3000, State: models.Listening, PID: 5678, ProcessName: "java.exe"},
	}

	conflicts := GetConflictsOnly(entries)
	if len(conflicts) != 1 {
		t.Fatalf("expected one real conflict, got %d", len(conflicts))
	}
	if !conflicts[0].HasConflict {
		t.Fatalf("expected conflict report to be marked as real conflict, got %+v", conflicts[0])
	}
}

func TestGetConflictsOnlyIgnoresIPv6WildcardWithLoopbackOnDifferentPIDs(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:5433", LocalPort: 5433, State: models.Listening, PID: 19992, ProcessName: "com.docker.backend.exe"},
		{Protocol: models.TCP, LocalAddress: "[::]:5433", LocalPort: 5433, State: models.Listening, PID: 19992, ProcessName: "com.docker.backend.exe"},
		{Protocol: models.TCP, LocalAddress: "[::1]:5433", LocalPort: 5433, State: models.Listening, PID: 21024, ProcessName: "wslrelay.exe"},
	}

	conflicts := GetConflictsOnly(entries)
	if len(conflicts) != 0 {
		t.Fatalf("expected no real conflict for docker+wsl cooperative binding, got %+v", conflicts)
	}
}

func TestGetConflictsOnlyReportsTwoWildcardBindings(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:8080", LocalPort: 8080, State: models.Listening, PID: 100, ProcessName: "app1.exe"},
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:8080", LocalPort: 8080, State: models.Listening, PID: 200, ProcessName: "app2.exe"},
	}

	conflicts := GetConflictsOnly(entries)
	if len(conflicts) != 1 || !conflicts[0].HasConflict {
		t.Fatalf("expected real conflict for two IPv4 wildcard bindings on same port, got %+v", conflicts)
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
