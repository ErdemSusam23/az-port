package cmd

import (
	"fmt"
	"time"

	"github.com/ErdemSusam23/az-port/internal/analyzer"
	"github.com/ErdemSusam23/az-port/internal/config"
	"github.com/ErdemSusam23/az-port/internal/scanner"
	"github.com/spf13/cobra"
)

var findCmd = &cobra.Command{
	Use:   "find [port...]",
	Short: "Find which process is using specific port(s)",
	Long: `Find which process is using a specific port or multiple ports.

Examples:
  az-port find 3000              # Find process using port 3000
  az-port find 8080,8081,3000   # Find processes using multiple ports
  az-port find 80 443 8080      # Find processes using multiple ports (space-separated)`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		executeFind(args)
	},
}

func init() {
	rootCmd.AddCommand(findCmd)
}

func executeFind(args []string) {
	start := time.Now()
	cfg, _, err := loadProjectConfig(configPath, mustGetwd())
	if err != nil {
		CheckErr(fmt.Errorf("failed to load config: %w", err))
		return
	}
	ports, err := parsePortsFromArgs(args)
	if err != nil {
		CheckErr(err)
		return
	}

	// Scan ports
	s := scanner.NewScanner()
	entries, err := s.ScanPorts()
	if err != nil {
		CheckErr(fmt.Errorf("failed to scan ports: %w", err))
		return
	}

	report := buildFindReport(entries, ports, config.ProjectConfig{
		SuggestRange: cfg.SuggestRange,
		SuggestCount: cfg.SuggestCount,
	})
	report.Metrics = calculateCommandMetrics(entries, report, start)

	if reportJSON {
		emitCommandReport(report, "")
		writeLocalMetricsIfEnabled(report)
		return
	}

	for _, port := range ports {
		portEntries := filterPortUsageEntries(entries, port)
		conflict := analyzer.GetConflictsWithPort(portEntries, port)
		fmt.Println()
		fmt.Println(buildPortStatusMessage(port, portEntries, conflict))
	}

	writeLocalMetricsIfEnabled(report)
}
