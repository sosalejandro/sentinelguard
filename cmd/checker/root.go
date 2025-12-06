package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/as-main/backdoor-checker/pkg/logger"
)

var (
	debug   bool
	verbose bool
)

var rootCmd = &cobra.Command{
	Use:   "backdoor-checker",
	Short: "A security tool to detect backdoors and suspicious activity",
	Long: `Backdoor Checker is a comprehensive security scanning tool
that analyzes your system for potential backdoors, persistence mechanisms,
suspicious processes, and other security threats.

It performs multiple scans including:
  - Network connections and listening ports
  - Running processes for suspicious patterns
  - Cron jobs and scheduled tasks
  - SSH configuration and authorized keys
  - Startup scripts and systemd services
  - Filesystem anomalies
  - User accounts and privileges`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logger.Init(debug)
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		logger.Sync()
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
