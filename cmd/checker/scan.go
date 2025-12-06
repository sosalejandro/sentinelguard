package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/infrastructure/platform"
	"github.com/as-main/backdoor-checker/internal/infrastructure/reporter"
	"github.com/as-main/backdoor-checker/internal/infrastructure/scanner"
	"github.com/as-main/backdoor-checker/internal/usecase"
	"github.com/as-main/backdoor-checker/pkg/logger"
)

var (
	scanners     []string
	parallel     bool
	maxParallel  int
	timeout      time.Duration
	outputFormat string
	prettyOutput bool
	pdfPaths     []string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run security scan for backdoors and suspicious activity",
	Long: `Performs a comprehensive security scan of the system looking for:
  - Suspicious network connections and listening ports
  - Malicious processes and reverse shells
  - Suspicious cron jobs and scheduled tasks
  - SSH misconfigurations and unauthorized keys
  - Persistence mechanisms (profile scripts, systemd, LD_PRELOAD)
  - Filesystem anomalies (SUID, hidden files)
  - Suspicious user accounts
  - Kernel rootkits and hidden modules
  - PAM backdoors and authentication bypass
  - Memory injection and hidden processes
  - Binary integrity and package tampering
  - Boot persistence (rc.local, GRUB, initramfs)
  - Malicious PDF files (JavaScript, launch actions, exploits)`,
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringSliceVarP(&scanners, "scanners", "s", nil, "Specific scanners to run (default: all)")
	scanCmd.Flags().BoolVarP(&parallel, "parallel", "p", true, "Run scanners in parallel")
	scanCmd.Flags().IntVarP(&maxParallel, "max-parallel", "m", 5, "Maximum parallel scanners")
	scanCmd.Flags().DurationVarP(&timeout, "timeout", "t", 5*time.Minute, "Scan timeout")
	scanCmd.Flags().StringVarP(&outputFormat, "format", "f", "console", "Output format: console, json, yaml")
	scanCmd.Flags().BoolVar(&prettyOutput, "pretty", true, "Pretty print JSON output")
	scanCmd.Flags().StringSliceVar(&pdfPaths, "pdf-paths", nil, "Custom paths for PDF scanner (default: /home, /tmp, /var/tmp)")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	log := logger.Get()

	// Detect platform
	platformInfo := platform.Detect()
	log.Debug("platform detected",
		zap.String("os", string(platformInfo.OS)),
		zap.String("environment", string(platformInfo.Environment)),
		zap.String("arch", platformInfo.Arch),
		zap.String("distro", platformInfo.Distro),
		zap.Bool("is_root", platformInfo.IsRoot),
	)

	log.Debug("initializing scan",
		zap.Strings("scanners", scanners),
		zap.Bool("parallel", parallel),
		zap.Int("max_parallel", maxParallel),
		zap.Duration("timeout", timeout),
	)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		color.Yellow("\n⚠️  Scan interrupted, cleaning up...")
		cancel()
	}()

	registry := scanner.NewRegistry()
	registerScanners(registry, platformInfo)

	scanUseCase := usecase.NewScanUseCase(registry)

	// Only print status messages for console output
	if outputFormat == "console" || outputFormat == "" {
		color.Cyan("🔍 Starting backdoor scan...")
		printPlatformInfo(platformInfo)
		fmt.Println()
	}

	opts := &usecase.ScanOptions{
		Scanners:    scanners,
		Parallel:    parallel,
		MaxParallel: maxParallel,
	}

	result, scanErrors := scanUseCase.Execute(ctx, opts)

	// Create reporter based on format
	factory := reporter.NewFactory()
	rep, err := factory.Create(outputFormat, verbose, prettyOutput)
	if err != nil {
		return err
	}

	if err := rep.Report(result, os.Stdout); err != nil {
		return err
	}

	if scanErrors != nil && scanErrors.HasErrors() && (outputFormat == "console" || outputFormat == "") {
		color.Yellow("\n⚠️  Some scanners encountered errors:")
		for _, e := range scanErrors.Errors {
			color.Yellow("  • %s: %v", e.ScannerName, e.Err)
		}
		fmt.Println()
	}

	if result.HasCriticalFindings() {
		os.Exit(2)
	}
	if result.HasHighFindings() {
		os.Exit(1)
	}

	return nil
}

func registerScanners(registry *scanner.Registry, platformInfo *platform.PlatformInfo) {
	log := logger.Get()
	log.Debug("registering scanners")

	// Cross-platform scanners
	registry.Register(scanner.NewNetworkScanner())
	registry.Register(scanner.NewProcessScanner())
	registry.Register(scanner.NewSSHScanner())
	registry.Register(scanner.NewFilesystemScanner())
	registry.Register(scanner.NewUserScanner())
	registry.Register(scanner.NewPersistenceScanner())
	if len(pdfPaths) > 0 {
		registry.Register(scanner.NewPDFScannerWithPaths(pdfPaths))
	} else {
		registry.Register(scanner.NewPDFScanner())
	}

	// Linux-specific scanners
	if platformInfo.OS == platform.OSLinux {
		registry.Register(scanner.NewCronScanner())
		registry.Register(scanner.NewKernelScanner())
		registry.Register(scanner.NewPAMScanner())
		registry.Register(scanner.NewMemoryScanner())
		registry.Register(scanner.NewIntegrityScanner())
		registry.Register(scanner.NewBootScanner())
	}

	// macOS-specific scanners would go here
	// if platformInfo.OS == platform.OSDarwin { ... }

	// Windows-specific scanners would go here
	// if platformInfo.OS == platform.OSWindows { ... }

	log.Debug("scanners registered",
		zap.Int("count", len(registry.GetAll())),
		zap.String("platform", string(platformInfo.OS)),
	)
}

func printPlatformInfo(info *platform.PlatformInfo) {
	envStr := ""
	if info.Environment != platform.EnvNative {
		envStr = fmt.Sprintf(" (%s)", info.Environment)
	}

	distroStr := ""
	if info.Distro != "" {
		distroStr = fmt.Sprintf(" %s", info.Distro)
		if info.Version != "" {
			distroStr += " " + info.Version
		}
	}

	rootStr := ""
	if info.IsRoot {
		rootStr = color.GreenString(" [root]")
	} else {
		rootStr = color.YellowString(" [user]")
	}

	fmt.Printf("Platform: %s%s %s%s%s\n",
		color.CyanString(string(info.OS)),
		distroStr,
		info.Arch,
		envStr,
		rootStr,
	)
}
