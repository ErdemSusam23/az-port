package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ErdemSusam23/az-port/internal/models"
)

func TestFormatCommandReportJSONIncludesSummaryFindingsAndMetrics(t *testing.T) {
	report := models.CommandReport{
		Command: "check",
		Summary: "1 port available, 1 port in use",
		Findings: []models.PortFinding{
			{Port: 3000, Status: models.PortStatusAvailable},
			{Port: 5432, Status: models.PortStatusInUse},
		},
		Recommendations: []string{"Use port 3001"},
		Metrics: models.CommandMetrics{
			DurationMs:            123,
			EntriesScanned:        40,
			FindingsCount:         2,
			ProcessResolutionRate: 0.9,
		},
	}

	output, err := formatCommandReportJSON(report)
	if err != nil {
		t.Fatalf("formatCommandReportJSON returned error: %v", err)
	}

	for _, fragment := range []string{
		`"command": "check"`,
		`"summary": "1 port available, 1 port in use"`,
		`"status": "available"`,
		`"status": "in_use"`,
		`"duration_ms": 123`,
	} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("expected JSON fragment %q in output %q", fragment, output)
		}
	}
}

func TestCalculateCommandMetricsCountsResolutionRate(t *testing.T) {
	entries := []models.PortEntry{
		{PID: 1, ProcessName: "node.exe"},
		{PID: 2, ProcessName: "N/A"},
		{PID: 0, ProcessName: "N/A"},
	}
	report := models.CommandReport{
		Findings: []models.PortFinding{{Port: 3000}, {Port: 5432}},
	}

	metrics := calculateCommandMetrics(entries, report, time.Now().Add(-150*time.Millisecond))
	if metrics.EntriesScanned != 3 {
		t.Fatalf("expected 3 entries scanned, got %+v", metrics)
	}
	if metrics.FindingsCount != 2 {
		t.Fatalf("expected 2 findings, got %+v", metrics)
	}
	if metrics.ProcessResolutionRate != 0.5 {
		t.Fatalf("expected resolution rate 0.5, got %+v", metrics)
	}
	if metrics.DurationMs <= 0 {
		t.Fatalf("expected positive duration, got %+v", metrics)
	}
}

func TestLoadProjectConfigReturnsDiscoveredConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "az-port.yaml"), []byte("expected_ports:\n  - 3000\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	cfg, path, err := loadProjectConfig("", root)
	if err != nil {
		t.Fatalf("loadProjectConfig returned error: %v", err)
	}
	if path == "" {
		t.Fatalf("expected config path to be discovered")
	}
	if len(cfg.ExpectedPorts) != 1 || cfg.ExpectedPorts[0] != 3000 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadProjectConfigReturnsEmptyWhenConfigMissing(t *testing.T) {
	cfg, path, err := loadProjectConfig("", t.TempDir())
	if err != nil {
		t.Fatalf("loadProjectConfig returned error: %v", err)
	}
	if path != "" {
		t.Fatalf("expected empty config path, got %q", path)
	}
	if len(cfg.ExpectedPorts) != 0 || len(cfg.CriticalPorts) != 0 || len(cfg.IgnorePorts) != 0 || cfg.SuggestRange != "" || cfg.SuggestCount != 0 {
		t.Fatalf("expected empty config, got %+v", cfg)
	}
}
