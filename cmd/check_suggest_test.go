package cmd

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ErdemSusam23/az-port/internal/config"
	"github.com/ErdemSusam23/az-port/internal/models"
)

func TestResolveCheckPortsFallsBackToConfigExpectedPorts(t *testing.T) {
	cfg := config.ProjectConfig{
		ExpectedPorts: []int{3000, 5432},
	}

	ports, err := resolveCheckPorts(nil, cfg)
	if err != nil {
		t.Fatalf("resolveCheckPorts returned error: %v", err)
	}
	if !reflect.DeepEqual(ports, []int{3000, 5432}) {
		t.Fatalf("unexpected ports: %+v", ports)
	}
}

func TestBuildCheckReportClassifiesAvailableAndInUsePorts(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:5432", LocalPort: 5432, State: models.Listening, PID: 6280, ProcessName: "postgres.exe"},
	}

	report := buildCheckReport(entries, []int{3000, 5432}, config.ProjectConfig{SuggestRange: "3000-3010", SuggestCount: 3})
	if report.Command != "check" {
		t.Fatalf("expected check command, got %+v", report)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %+v", report.Findings)
	}
	if report.Findings[0].Status != models.PortStatusAvailable {
		t.Fatalf("expected first port to be available, got %+v", report.Findings[0])
	}
	if report.Findings[1].Status != models.PortStatusInUse {
		t.Fatalf("expected second port to be in use, got %+v", report.Findings[1])
	}
	if !strings.Contains(strings.Join(report.Recommendations, " "), "3001") {
		t.Fatalf("expected a suggestion recommendation, got %+v", report.Recommendations)
	}
}

func TestBuildSuggestReportReturnsAvailablePortsInRange(t *testing.T) {
	entries := []models.PortEntry{
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:3000", LocalPort: 3000, State: models.Listening, PID: 101, ProcessName: "node.exe"},
		{Protocol: models.TCP, LocalAddress: "127.0.0.1:3001", LocalPort: 3001, State: models.Listening, PID: 102, ProcessName: "vite.exe"},
	}

	report, err := buildSuggestReport(entries, "3000-3005", 3)
	if err != nil {
		t.Fatalf("buildSuggestReport returned error: %v", err)
	}

	if report.Command != "suggest" {
		t.Fatalf("expected suggest command, got %+v", report)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("expected 3 suggested findings, got %+v", report.Findings)
	}
	expectedPorts := []int{3002, 3003, 3004}
	for i, expected := range expectedPorts {
		if report.Findings[i].Port != expected {
			t.Fatalf("expected port %d at index %d, got %+v", expected, i, report.Findings[i])
		}
		if report.Findings[i].Status != models.PortStatusSuggested {
			t.Fatalf("expected suggested status, got %+v", report.Findings[i])
		}
	}
}
