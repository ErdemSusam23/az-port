package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ErdemSusam23/az-port/internal/scanner"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check [port...]",
	Short: "Check whether required ports are available before startup",
	Long: `Check whether one or more ports are available before starting an app.

Examples:
  az-port check 3000
  az-port check 3000 5432
  az-port check                    # Uses expected_ports from az-port.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		executeCheck(args)
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}

func executeCheck(args []string) {
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
	ports, err = resolveCheckPorts(ports, cfg)
	if err != nil {
		CheckErr(err)
		return
	}

	s := scanner.NewScanner()
	entries, err := s.ScanPorts()
	if err != nil {
		CheckErr(fmt.Errorf("failed to scan ports: %w", err))
		return
	}

	report := buildCheckReport(entries, ports, cfg)
	report.Metrics = calculateCommandMetrics(entries, report, start)

	emitCommandReport(report, formatHumanReport(report))
	writeLocalMetricsIfEnabled(report)

	if hasUnavailableFindings(report.Findings) {
		os.Exit(1)
	}
}

func parsePortsFromArgs(args []string) ([]int, error) {
	var ports []int
	for _, arg := range args {
		parts := strings.Split(arg, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			port, err := strconv.Atoi(part)
			if err != nil || port < 1 || port > 65535 {
				return nil, fmt.Errorf("invalid port number: %s", part)
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}
