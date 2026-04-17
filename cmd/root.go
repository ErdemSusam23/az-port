package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	reportJSON      bool
	configPath      string
	metricsLocalPath string
)

var rootCmd = &cobra.Command{
	Use:   "az-port",
	Short: "Port conflict analysis tool",
	Long: `az-port is a CLI tool that analyzes active port usage, detects port conflicts,
and shows developers which process is using which port.

Features:
  - List all active ports and their associated processes
  - Find which process is using a specific port
  - Detect potential port conflicts
  - Filter by port range, process name, or PID
  - Multiple output formats (table, JSON, CSV)`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global flags can be added here
	rootCmd.PersistentFlags().BoolVar(&reportJSON, "report-json", false, "Output structured JSON report")
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to az-port project config file")
	rootCmd.PersistentFlags().StringVar(&metricsLocalPath, "metrics-local", "", "Append local command metrics to the given JSONL file")
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "help [command]",
		Hidden: true,
	})
	rootCmd.SetUsageTemplate(`Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}
`)
}

// GetRootCmd returns the root command for testing
func GetRootCmd() *cobra.Command {
	return rootCmd
}

func CheckErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
