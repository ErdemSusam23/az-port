package cmd

import (
	"fmt"
	"time"

	"github.com/ErdemSusam23/az-port/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	suggestRange string
	suggestCount int
)

var suggestCmd = &cobra.Command{
	Use:   "suggest",
	Short: "Suggest available ports in a range",
	Long: `Suggest currently available ports for local development.

Examples:
  az-port suggest
  az-port suggest --range 3000-3999
  az-port suggest --range 3000-3999 --count 5`,
	Run: func(cmd *cobra.Command, args []string) {
		executeSuggest()
	},
}

func init() {
	rootCmd.AddCommand(suggestCmd)
	suggestCmd.Flags().StringVar(&suggestRange, "range", "", "Port range to scan (e.g. 3000-3999)")
	suggestCmd.Flags().IntVar(&suggestCount, "count", 5, "Number of ports to suggest")
}

func executeSuggest() {
	start := time.Now()
	cfg, _, err := loadProjectConfig(configPath, mustGetwd())
	if err != nil {
		CheckErr(fmt.Errorf("failed to load config: %w", err))
		return
	}

	rangeValue := suggestRange
	if rangeValue == "" {
		rangeValue = cfg.SuggestRange
	}
	count := suggestCount
	if count == 5 && cfg.SuggestCount > 0 {
		count = cfg.SuggestCount
	}

	s := scanner.NewScanner()
	entries, err := s.ScanPorts()
	if err != nil {
		CheckErr(fmt.Errorf("failed to scan ports: %w", err))
		return
	}

	report, err := buildSuggestReport(entries, rangeValue, count)
	if err != nil {
		CheckErr(err)
		return
	}
	report.Metrics = calculateCommandMetrics(entries, report, start)

	emitCommandReport(report, formatHumanReport(report))
	writeLocalMetricsIfEnabled(report)
}
