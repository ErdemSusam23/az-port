package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ErdemSusam23/az-port/internal/config"
	localmetrics "github.com/ErdemSusam23/az-port/internal/metrics"
	"github.com/ErdemSusam23/az-port/internal/models"
)

func formatCommandReportJSON(report models.CommandReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func calculateCommandMetrics(entries []models.PortEntry, report models.CommandReport, start time.Time) models.CommandMetrics {
	resolved := 0
	resolvable := 0
	for _, entry := range entries {
		if entry.PID <= 0 {
			continue
		}
		resolvable++
		if entry.ProcessName != "" && entry.ProcessName != "N/A" {
			resolved++
		}
	}

	rate := 1.0
	if resolvable > 0 {
		rate = float64(resolved) / float64(resolvable)
	}

	return models.CommandMetrics{
		DurationMs:            time.Since(start).Milliseconds(),
		EntriesScanned:        len(entries),
		FindingsCount:         len(report.Findings),
		ProcessResolutionRate: rate,
	}
}

func loadProjectConfig(configPath string, cwd string) (config.ProjectConfig, string, error) {
	if configPath != "" {
		cfg, err := config.LoadProjectConfig(configPath)
		return cfg, configPath, err
	}

	path, err := config.DiscoverProjectConfig(cwd)
	if err != nil {
		if os.IsNotExist(err) {
			return config.ProjectConfig{}, "", nil
		}
		return config.ProjectConfig{}, "", err
	}

	cfg, err := config.LoadProjectConfig(path)
	return cfg, path, err
}

func emitCommandReport(report models.CommandReport, textOutput string) {
	if reportJSON {
		output, err := formatCommandReportJSON(report)
		if err != nil {
			CheckErr(fmt.Errorf("failed to format command report: %w", err))
			return
		}
		fmt.Println(output)
		return
	}

	fmt.Println(textOutput)
}

func writeLocalMetricsIfEnabled(report models.CommandReport) {
	if metricsLocalPath == "" {
		return
	}

	event := localmetrics.Event{
		Timestamp:             time.Now().UTC(),
		Command:               report.Command,
		DurationMs:            report.Metrics.DurationMs,
		EntriesScanned:        report.Metrics.EntriesScanned,
		FindingsCount:         report.Metrics.FindingsCount,
		ProcessResolutionRate: report.Metrics.ProcessResolutionRate,
	}

	if err := localmetrics.AppendLocalEvent(metricsLocalPath, event); err != nil {
		CheckErr(fmt.Errorf("failed to write local metrics: %w", err))
	}
}
