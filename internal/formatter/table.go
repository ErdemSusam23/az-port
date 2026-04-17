package formatter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ErdemSusam23/az-port/internal/models"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

// FormatType represents the output format
type FormatType string

const (
	TableFormat FormatType = "table"
	JSONFormat  FormatType = "json"
	CSVFormat   FormatType = "csv"
)

// FormatOutput formats port entries according to the specified format
func FormatOutput(entries []models.PortEntry, format FormatType) (string, error) {
	switch format {
	case TableFormat:
		return formatTable(entries)
	case JSONFormat:
		return formatJSON(entries)
	case CSVFormat:
		return formatCSV(entries)
	default:
		return formatTable(entries)
	}
}

// formatTable formats entries as a table using tablewriter v1.0+
func formatTable(entries []models.PortEntry) (string, error) {
	if len(entries) == 0 {
		return "No ports found.", nil
	}

	var buf bytes.Buffer
	table := tablewriter.NewTable(&buf)
	
	// Set header
	table.Header("PROTO", "PORT", "BIND", "STATE", "PID", "PROCESS")

	// Prepare data
	var data [][]any
	for _, entry := range entries {
		bind := formatBindAddress(entry.LocalAddress, entry.LocalPort)
		data = append(data, []any{
			string(entry.Protocol),
			fmt.Sprintf("%d", entry.LocalPort),
			bind,
			string(entry.State),
			fmt.Sprintf("%d", entry.PID),
			entry.ProcessName,
		})
	}
	
	table.Bulk(data)
	table.Render()
	
	return buf.String(), nil
}

// formatJSON formats entries as JSON
func formatJSON(entries []models.PortEntry) (string, error) {
	if entries == nil {
		entries = []models.PortEntry{}
	}
	output, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %w", err)
	}
	return string(output), nil
}

// formatCSV formats entries as CSV
func formatCSV(entries []models.PortEntry) (string, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	
	// Write header
	if err := writer.Write([]string{"Protocol", "LocalAddress", "State", "PID", "ProcessName", "ProcessPath", "User"}); err != nil {
		return "", fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write data
	for _, entry := range entries {
		record := []string{
			string(entry.Protocol),
			entry.LocalAddress,
			string(entry.State),
			fmt.Sprintf("%d", entry.PID),
			entry.ProcessName,
			entry.ProcessPath,
			entry.User,
		}
		if err := writer.Write(record); err != nil {
			return "", fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", fmt.Errorf("CSV writer error: %w", err)
	}

	return buf.String(), nil
}

// PrintTable prints entries directly to stdout (for commands)
func PrintTable(entries []models.PortEntry) {
	table := tablewriter.NewTable(os.Stdout)
	
	table.Header("PROTO", "PORT", "BIND", "STATE", "PID", "PROCESS")

	var data [][]any
	for _, entry := range entries {
		state := string(entry.State)
		bind := formatBindAddress(entry.LocalAddress, entry.LocalPort)
		
		// Colorize state
		switch entry.State {
		case models.Listening:
			state = color.GreenString(string(entry.State))
		case models.Established:
			state = color.GreenString(string(entry.State))
		case models.TimeWait, models.CloseWait:
			state = color.YellowString(string(entry.State))
		case models.Closing, models.LastAck:
			state = color.RedString(string(entry.State))
		}

		data = append(data, []any{
			string(entry.Protocol),
			fmt.Sprintf("%d", entry.LocalPort),
			bind,
			state,
			fmt.Sprintf("%d", entry.PID),
			entry.ProcessName,
		})
	}
	
	table.Bulk(data)
	table.Render()
}

// PrintConflictTable prints conflict entries with risk level
func PrintConflictTable(reports []models.ConflictReport) {
	table := tablewriter.NewTable(os.Stdout)
	
	table.Header("PORT", "RISK", "PROCESSES")

	var data [][]any
	for _, report := range reports {
		risk := string(report.RiskLevel)
		
		// Colorize risk
		switch report.RiskLevel {
		case models.High:
			risk = color.RedString(string(report.RiskLevel))
		case models.Medium:
			risk = color.YellowString(string(report.RiskLevel))
		case models.Low:
			risk = color.GreenString(string(report.RiskLevel))
		}

		processes := summarizeProcesses(report.Entries)

		data = append(data, []any{
			fmt.Sprintf("%d", report.Port),
			risk,
			strings.Join(processes, ", "),
		})
	}
	
	table.Bulk(data)
	table.Render()
}

// FormatAsReader returns a reader with formatted output
func FormatAsReader(entries []models.PortEntry, format FormatType) (io.Reader, error) {
	output, err := FormatOutput(entries, format)
	if err != nil {
		return nil, err
	}
	return strings.NewReader(output), nil
}

func formatBindAddress(localAddress string, localPort int) string {
	portSuffix := fmt.Sprintf(":%d", localPort)
	return strings.TrimSuffix(localAddress, portSuffix)
}

func summarizeProcesses(entries []models.PortEntry) []string {
	seen := make(map[int]struct{})
	var labels []string

	for _, entry := range entries {
		if _, ok := seen[entry.PID]; ok {
			continue
		}
		seen[entry.PID] = struct{}{}
		labels = append(labels, fmt.Sprintf("%s (PID: %d)", entry.ProcessName, entry.PID))
	}

	if len(labels) <= 3 {
		return labels
	}

	return append(labels[:3], fmt.Sprintf("+%d more", len(labels)-3))
}
