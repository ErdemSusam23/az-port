//go:build windows
// +build windows

package scanner

import (
	"errors"
	"testing"

	"github.com/ErdemSusam23/az-port/internal/models"
)

func TestParseNetstatOutputParsesTCPAndUDP(t *testing.T) {
	input := "Active Connections\r\n\r\n" +
		"  Proto  Local Address          Foreign Address        State           PID\r\n" +
		"  TCP    0.0.0.0:5432           0.0.0.0:0              LISTENING       6280\r\n" +
		"  UDP    127.0.0.1:1900         *:*                                    4242\r\n"

	s := &WindowsScanner{}
	entries, err := s.parseNetstatOutput(input)
	if err != nil {
		t.Fatalf("parseNetstatOutput returned error: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	if entries[0].Protocol != models.TCP || entries[0].LocalPort != 5432 || entries[0].PID != 6280 {
		t.Fatalf("unexpected TCP entry: %+v", entries[0])
	}

	if entries[1].Protocol != models.UDP {
		t.Fatalf("expected UDP protocol, got %s", entries[1].Protocol)
	}
	if entries[1].LocalPort != 1900 {
		t.Fatalf("expected UDP local port 1900, got %d", entries[1].LocalPort)
	}
	if entries[1].PID != 4242 {
		t.Fatalf("expected UDP PID 4242, got %d", entries[1].PID)
	}
	if entries[1].State != models.Listening {
		t.Fatalf("expected UDP state %s, got %s", models.Listening, entries[1].State)
	}
}

func TestEnrichEntriesWithProcessInfoPopulatesKnownProcesses(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "N/A"},
		{Protocol: models.TCP, LocalAddress: "[::]:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "N/A"},
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:5037", LocalPort: 5037, State: models.Established, PID: 0, ProcessName: "N/A"},
	}

	s := &WindowsScanner{}
	enriched := s.enrichEntriesWithProcessInfo(entries, func(pid int) (string, string, string, error) {
		if pid != 6280 {
			return "", "", "", errors.New("unexpected pid")
		}
		return "postgres.exe", "C:\\Postgres\\bin\\postgres.exe", "ersus", nil
	})

	if enriched[0].ProcessName != "postgres.exe" || enriched[1].ProcessName != "postgres.exe" {
		t.Fatalf("expected known process names to be populated, got %+v", enriched)
	}
	if enriched[0].ProcessPath == "" || enriched[0].User == "" {
		t.Fatalf("expected process details to be populated, got %+v", enriched[0])
	}
	if enriched[2].ProcessName != "N/A" {
		t.Fatalf("expected PID 0 entry to remain unchanged, got %+v", enriched[2])
	}
}

func TestParseTasklistOutputReturnsProcessNamesByPID(t *testing.T) {
	input := "\"postgres.exe\",\"6280\",\"Services\",\"0\",\"20,000 K\"\r\n" +
		"\"adb.exe\",\"6808\",\"Console\",\"1\",\"10,000 K\"\r\n"

	s := &WindowsScanner{}
	processes, err := s.parseTasklistOutput(input)
	if err != nil {
		t.Fatalf("parseTasklistOutput returned error: %v", err)
	}

	if processes[6280].name != "postgres.exe" {
		t.Fatalf("expected postgres.exe for pid 6280, got %+v", processes[6280])
	}
	if processes[6808].name != "adb.exe" {
		t.Fatalf("expected adb.exe for pid 6808, got %+v", processes[6808])
	}
}

func TestParsePowerShellProcessListOutputReturnsProcessNamesByPID(t *testing.T) {
	input := "\"Id\",\"ProcessName\"\r\n" +
		"\"6280\",\"postgres\"\r\n" +
		"\"6808\",\"adb\"\r\n"

	s := &WindowsScanner{}
	processes, err := s.parsePowerShellProcessListOutput(input)
	if err != nil {
		t.Fatalf("parsePowerShellProcessListOutput returned error: %v", err)
	}

	if processes[6280].name != "postgres.exe" {
		t.Fatalf("expected postgres.exe for pid 6280, got %+v", processes[6280])
	}
	if processes[6808].name != "adb.exe" {
		t.Fatalf("expected adb.exe for pid 6808, got %+v", processes[6808])
	}
}

func TestEnrichEntriesWithBulkProcessInfoUsesTasklistNames(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "0.0.0.0:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "N/A"},
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:5037", LocalPort: 5037, State: models.Listening, PID: 6808, ProcessName: "N/A"},
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:5037", LocalPort: 5037, State: models.TimeWait, PID: 0, ProcessName: "N/A"},
	}

	s := &WindowsScanner{}
	enriched := s.enrichEntriesWithBulkProcessInfo(entries, map[int]processInfo{
		6280: {name: "postgres.exe"},
		6808: {name: "adb.exe"},
	})

	if enriched[0].ProcessName != "postgres.exe" {
		t.Fatalf("expected postgres.exe, got %+v", enriched[0])
	}
	if enriched[1].ProcessName != "adb.exe" {
		t.Fatalf("expected adb.exe, got %+v", enriched[1])
	}
	if enriched[2].ProcessName != "N/A" {
		t.Fatalf("expected PID 0 entry to remain unchanged, got %+v", enriched[2])
	}
}
