package cmd

import (
	"fmt"
	"time"

	"github.com/ErdemSusam23/az-port/internal/analyzer"
	"github.com/ErdemSusam23/az-port/internal/config"
	"github.com/ErdemSusam23/az-port/internal/formatter"
	"github.com/ErdemSusam23/az-port/internal/scanner"
	"github.com/spf13/cobra"
)

var conflictsCmd = &cobra.Command{
	Use:   "conflicts",
	Short: "Detect potential port conflicts",
	Long: `Detect and report potential port conflicts on the system.

Examples:
  az-port conflicts                 # Show all conflicts
  az-port conflicts --port 3000     # Check specific port`,
	Run: func(cmd *cobra.Command, args []string) {
		executeConflicts()
	},
}

var checkPort int

func init() {
	rootCmd.AddCommand(conflictsCmd)
	conflictsCmd.Flags().IntVar(&checkPort, "port", 0, "Check specific port")
}

func executeConflicts() {
	start := time.Now()
	// Scan ports
	s := scanner.NewScanner()
	entries, err := s.ScanPorts()
	if err != nil {
		CheckErr(fmt.Errorf("failed to scan ports: %w", err))
		return
	}

	if checkPort > 0 {
		// Check specific port
		report := analyzer.GetConflictsWithPort(entries, checkPort)
		portEntries := filterPortUsageEntries(entries, checkPort)
		commandReport := buildFindReport(entries, []int{checkPort}, config.ProjectConfig{})
		commandReport.Command = "conflicts"
		commandReport.Metrics = calculateCommandMetrics(entries, commandReport, start)
		if reportJSON {
			emitCommandReport(commandReport, "")
		} else {
			fmt.Println(buildPortStatusMessage(checkPort, portEntries, report))
		}
		writeLocalMetricsIfEnabled(commandReport)
	} else {
		// Check all conflicts
		conflicts := analyzer.GetConflictsOnly(entries)
		commandReport := buildConflictsReport(entries)
		commandReport.Metrics = calculateCommandMetrics(entries, commandReport, start)

		if reportJSON {
			emitCommandReport(commandReport, "")
			writeLocalMetricsIfEnabled(commandReport)
			return
		}
		
		fmt.Println("Port Conflict Report:")
		fmt.Println()
		
		if len(conflicts) == 0 {
			fmt.Println("No port conflicts detected.")
			writeLocalMetricsIfEnabled(commandReport)
			return
		}

		formatter.PrintConflictTable(conflicts)
		
		fmt.Printf("\nWARNING: %d potential conflict(s) detected.\n", len(conflicts))
		writeLocalMetricsIfEnabled(commandReport)
	}
}
