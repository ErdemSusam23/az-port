package cmd

import (
	"fmt"
	"time"

	"github.com/ErdemSusam23/az-port/internal/formatter"
	"github.com/ErdemSusam23/az-port/internal/models"
	"github.com/ErdemSusam23/az-port/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	listProtocol   string
	listState      string
	listPortMin    int
	listPortMax    int
	listProcessName string
	listPID        int
	listFormat     string
	listTCP        bool
	listUDP        bool
	listListening  bool
	listAllStates  bool
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active ports",
	Long: `List all active ports and their associated processes.

Examples:
  az-port list                      # List all ports
  az-port list --tcp                # List only TCP ports
  az-port list --udp                # List only UDP ports
  az-port list --listening          # List only listening ports
  az-port list --port 3000-4000     # List ports in range
  az-port list --name "node"        # Filter by process name
  az-port list --pid 1234           # Filter by PID
  az-port list --format json        # Output as JSON`,
	Run: func(cmd *cobra.Command, args []string) {
		executeList(cmd)
	},
}

func init() {
	rootCmd.AddCommand(listCmd)

	listCmd.Flags().BoolVar(&listTCP, "tcp", false, "Show only TCP ports")
	listCmd.Flags().BoolVar(&listUDP, "udp", false, "Show only UDP ports")
	listCmd.Flags().BoolVar(&listListening, "listening", false, "Show only listening ports")
	listCmd.Flags().BoolVar(&listAllStates, "all-states", false, "Show all connection states")
	listCmd.Flags().StringVar(&listFormat, "format", "table", "Output format (table, json, csv)")
	listCmd.Flags().IntVar(&listPortMin, "port-min", 0, "Minimum port number")
	listCmd.Flags().IntVar(&listPortMax, "port-max", 65535, "Maximum port number")
	listCmd.Flags().StringVar(&listProcessName, "name", "", "Filter by process name")
	listCmd.Flags().IntVar(&listPID, "pid", 0, "Filter by PID")

	// Port range shorthand
	listCmd.Flags().String("port", "", "Port range (e.g., 3000-4000)")
}

func executeList(cmd *cobra.Command) {
	start := time.Now()
	// Create scanner and scan
	s := scanner.NewScanner()
	entries, err := s.ScanPorts()
	if err != nil {
		CheckErr(fmt.Errorf("failed to scan ports: %w", err))
		return
	}

	// Build filter options
	opts := scanner.ScanOptions{
		PortMin:     listPortMin,
		PortMax:     listPortMax,
		ProcessName: listProcessName,
		PID:         listPID,
	}

	// Handle protocol flags
	if listTCP {
		opts.Protocol = models.TCP
	}
	if listUDP {
		opts.Protocol = models.UDP
	}

	// Default to developer-focused listening ports unless all states are requested.
	if !listAllStates || listListening {
		opts.State = models.Listening
	}

	// Handle port range shorthand
	if portRangeFlag := cmd.Flags().Lookup("port"); portRangeFlag != nil && portRangeFlag.Changed {
		var min, max int
		_, err := fmt.Sscanf(portRangeFlag.Value.String(), "%d-%d", &min, &max)
		if err != nil {
			CheckErr(fmt.Errorf("invalid port range format: %s", portRangeFlag.Value.String()))
			return
		}
		opts.PortMin = min
		opts.PortMax = max
	}

	// Apply filters
	var filtered []models.PortEntry
	for _, entry := range entries {
		if scanner.MatchOptions(entry, opts) {
			filtered = append(filtered, entry)
		}
	}

	// Format and print
	formatType := formatter.FormatType(listFormat)
	output, err := formatter.FormatOutput(filtered, formatType)
	if err != nil {
		CheckErr(fmt.Errorf("failed to format output: %w", err))
		return
	}

	report := buildListReport(filtered)
	report.Metrics = calculateCommandMetrics(entries, report, start)

	if reportJSON {
		emitCommandReport(report, "")
		writeLocalMetricsIfEnabled(report)
		return
	}

	fmt.Println(output)
	fmt.Printf("\nTotal: %d ports\n", len(filtered))
	writeLocalMetricsIfEnabled(report)
}
