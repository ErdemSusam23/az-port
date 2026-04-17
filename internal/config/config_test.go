package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseProjectConfigParsesExpectedFields(t *testing.T) {
	data := []byte(`
expected_ports:
  - 3000
  - 5432
critical_ports:
  - 3000
ignore_ports:
  - 5353
suggest_range: 3000-3999
suggest_count: 5
`)

	cfg, err := ParseProjectConfig(data)
	if err != nil {
		t.Fatalf("ParseProjectConfig returned error: %v", err)
	}

	if !reflect.DeepEqual(cfg.ExpectedPorts, []int{3000, 5432}) {
		t.Fatalf("unexpected expected ports: %+v", cfg.ExpectedPorts)
	}
	if !reflect.DeepEqual(cfg.CriticalPorts, []int{3000}) {
		t.Fatalf("unexpected critical ports: %+v", cfg.CriticalPorts)
	}
	if !reflect.DeepEqual(cfg.IgnorePorts, []int{5353}) {
		t.Fatalf("unexpected ignore ports: %+v", cfg.IgnorePorts)
	}
	if cfg.SuggestRange != "3000-3999" {
		t.Fatalf("unexpected suggest range: %q", cfg.SuggestRange)
	}
	if cfg.SuggestCount != 5 {
		t.Fatalf("unexpected suggest count: %d", cfg.SuggestCount)
	}
}

func TestDiscoverProjectConfigFindsNearestAzPortYAML(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "apps", "api")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}

	expectedPath := filepath.Join(root, "az-port.yaml")
	if err := os.WriteFile(expectedPath, []byte("expected_ports:\n  - 3000\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	path, err := DiscoverProjectConfig(nested)
	if err != nil {
		t.Fatalf("DiscoverProjectConfig returned error: %v", err)
	}
	if path != expectedPath {
		t.Fatalf("expected config path %q, got %q", expectedPath, path)
	}
}
