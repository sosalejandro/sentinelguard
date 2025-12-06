package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/as-main/backdoor-checker/internal/infrastructure/platform"
	"github.com/as-main/backdoor-checker/internal/infrastructure/scanner"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available scanners",
	Long:  `Lists all available security scanners and their descriptions.`,
	Run:   runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) {
	platformInfo := platform.Detect()

	registry := scanner.NewRegistry()
	registerScanners(registry, platformInfo)

	scanners := registry.GetAll()

	color.Cyan("Available Scanners:\n")
	printPlatformInfo(platformInfo)
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tDESCRIPTION")
	fmt.Fprintln(w, "----\t-----------")

	for _, s := range scanners {
		fmt.Fprintf(w, "%s\t%s\n", s.Name(), s.Description())
	}

	w.Flush()
	fmt.Println()
	color.White("Use 'backdoor-checker scan -s <scanner1>,<scanner2>' to run specific scanners")
}
