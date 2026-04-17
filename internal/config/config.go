package config

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProjectConfig describes project-level defaults for check and suggest flows.
type ProjectConfig struct {
	ExpectedPorts []int
	CriticalPorts []int
	IgnorePorts   []int
	SuggestRange  string
	SuggestCount  int
}

// ParseProjectConfig parses a narrow YAML subset used by az-port project configs.
func ParseProjectConfig(data []byte) (ProjectConfig, error) {
	var cfg ProjectConfig
	scanner := bufio.NewScanner(bytes.NewReader(data))
	currentList := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "- ") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "- "))
			port, err := strconv.Atoi(value)
			if err != nil {
				return ProjectConfig{}, fmt.Errorf("invalid port value %q", value)
			}
			switch currentList {
			case "expected_ports":
				cfg.ExpectedPorts = append(cfg.ExpectedPorts, port)
			case "critical_ports":
				cfg.CriticalPorts = append(cfg.CriticalPorts, port)
			case "ignore_ports":
				cfg.IgnorePorts = append(cfg.IgnorePorts, port)
			default:
				return ProjectConfig{}, fmt.Errorf("list item without a supported key: %q", line)
			}
			continue
		}

		currentList = ""
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return ProjectConfig{}, fmt.Errorf("invalid config line %q", line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "expected_ports", "critical_ports", "ignore_ports":
			if value != "" {
				return ProjectConfig{}, fmt.Errorf("list key %q must not have inline value", key)
			}
			currentList = key
		case "suggest_range":
			cfg.SuggestRange = value
		case "suggest_count":
			count, err := strconv.Atoi(value)
			if err != nil {
				return ProjectConfig{}, fmt.Errorf("invalid suggest_count %q", value)
			}
			cfg.SuggestCount = count
		default:
			return ProjectConfig{}, fmt.Errorf("unsupported config key %q", key)
		}
	}

	if err := scanner.Err(); err != nil {
		return ProjectConfig{}, err
	}

	if cfg.SuggestCount == 0 {
		cfg.SuggestCount = 5
	}

	return cfg, nil
}

// LoadProjectConfig reads and parses an az-port config file.
func LoadProjectConfig(path string) (ProjectConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ProjectConfig{}, err
	}
	return ParseProjectConfig(data)
}

// DiscoverProjectConfig walks upward from cwd to find az-port.yaml or az-port.yml.
func DiscoverProjectConfig(cwd string) (string, error) {
	dir := cwd
	for {
		for _, name := range []string{"az-port.yaml", "az-port.yml"} {
			path := filepath.Join(dir, name)
			if _, err := os.Stat(path); err == nil {
				return path, nil
			}
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
