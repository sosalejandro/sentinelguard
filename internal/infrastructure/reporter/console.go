package reporter

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type ConsoleReporter struct {
	verbose bool
}

func NewConsoleReporter(verbose bool) *ConsoleReporter {
	return &ConsoleReporter{
		verbose: verbose,
	}
}

func (r *ConsoleReporter) Format() string {
	return "console"
}

func (r *ConsoleReporter) Report(result *entity.ScanResult, w io.Writer) error {
	r.printHeader(w, result)
	r.printSummary(w, result)

	if len(result.Findings) > 0 {
		r.printFindings(w, result)
	}

	r.printFooter(w, result)
	return nil
}

func (r *ConsoleReporter) printHeader(w io.Writer, result *entity.ScanResult) {
	fmt.Fprintln(w)
	color.New(color.FgCyan, color.Bold).Fprintln(w, "╔════════════════════════════════════════════════════════════╗")
	color.New(color.FgCyan, color.Bold).Fprintln(w, "║           BACKDOOR CHECKER SCAN REPORT                     ║")
	color.New(color.FgCyan, color.Bold).Fprintln(w, "╚════════════════════════════════════════════════════════════╝")
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Scan ID:      %s\n", result.ID)
	fmt.Fprintf(w, "Start Time:   %s\n", result.StartTime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Duration:     %s\n", result.Summary.Duration)
	fmt.Fprintf(w, "Status:       %s\n", r.colorStatus(result.Status))
	fmt.Fprintln(w)
}

func (r *ConsoleReporter) printSummary(w io.Writer, result *entity.ScanResult) {
	color.New(color.FgYellow, color.Bold).Fprintln(w, "─── SUMMARY ───────────────────────────────────────────────────")
	fmt.Fprintln(w)

	summary := result.Summary
	fmt.Fprintf(w, "Scanners Executed: %d\n", len(summary.ScannersExecuted))
	if r.verbose {
		for _, scanner := range summary.ScannersExecuted {
			fmt.Fprintf(w, "  • %s\n", scanner)
		}
	}
	fmt.Fprintln(w)

	fmt.Fprintf(w, "Total Findings: %d\n", summary.TotalFindings)
	fmt.Fprintln(w)

	r.printSeverityCount(w, "CRITICAL", summary.CriticalCount, color.FgRed, color.Bold)
	r.printSeverityCount(w, "HIGH", summary.HighCount, color.FgHiRed)
	r.printSeverityCount(w, "MEDIUM", summary.MediumCount, color.FgYellow)
	r.printSeverityCount(w, "LOW", summary.LowCount, color.FgBlue)
	r.printSeverityCount(w, "INFO", summary.InfoCount, color.FgWhite)
	fmt.Fprintln(w)
}

func (r *ConsoleReporter) printSeverityCount(w io.Writer, name string, count int, attrs ...color.Attribute) {
	c := color.New(attrs...)
	bar := strings.Repeat("█", min(count, 20))
	c.Fprintf(w, "  %-8s [%3d] %s\n", name, count, bar)
}

func (r *ConsoleReporter) printFindings(w io.Writer, result *entity.ScanResult) {
	color.New(color.FgYellow, color.Bold).Fprintln(w, "─── FINDINGS ──────────────────────────────────────────────────")
	fmt.Fprintln(w)

	groupedFindings := r.groupByCategory(result.Findings)

	for category, findings := range groupedFindings {
		color.New(color.FgCyan, color.Bold).Fprintf(w, "▸ %s (%d)\n", category, len(findings))
		fmt.Fprintln(w)

		for _, f := range findings {
			r.printFinding(w, f)
		}
	}
}

func (r *ConsoleReporter) printFinding(w io.Writer, f *entity.Finding) {
	severityColor := r.getSeverityColor(f.Severity)

	severityColor.Fprintf(w, "  [%s] ", f.Severity.String())
	fmt.Fprintln(w, f.Title)

	color.New(color.FgWhite).Fprintf(w, "    %s\n", f.Description)

	if f.Path != "" {
		color.New(color.FgHiBlack).Fprintf(w, "    Path: %s\n", f.Path)
	}

	if r.verbose && len(f.Details) > 0 {
		for key, value := range f.Details {
			color.New(color.FgHiBlack).Fprintf(w, "    %s: %v\n", key, value)
		}
	}

	fmt.Fprintln(w)
}

func (r *ConsoleReporter) printFooter(w io.Writer, result *entity.ScanResult) {
	color.New(color.FgYellow, color.Bold).Fprintln(w, "─── VERDICT ───────────────────────────────────────────────────")
	fmt.Fprintln(w)

	if result.Summary.CriticalCount > 0 {
		color.New(color.FgRed, color.Bold).Fprintln(w, "  ⚠️  CRITICAL ISSUES DETECTED - IMMEDIATE ACTION REQUIRED")
	} else if result.Summary.HighCount > 0 {
		color.New(color.FgHiRed).Fprintln(w, "  ⚠️  HIGH SEVERITY ISSUES DETECTED - INVESTIGATION RECOMMENDED")
	} else if result.Summary.MediumCount > 0 {
		color.New(color.FgYellow).Fprintln(w, "  ⚡ MEDIUM SEVERITY ISSUES DETECTED - REVIEW RECOMMENDED")
	} else if result.Summary.TotalFindings > 0 {
		color.New(color.FgBlue).Fprintln(w, "  ℹ️  LOW SEVERITY FINDINGS - INFORMATIONAL")
	} else {
		color.New(color.FgGreen, color.Bold).Fprintln(w, "  ✅ NO SUSPICIOUS ACTIVITY DETECTED")
	}

	fmt.Fprintln(w)
}

func (r *ConsoleReporter) colorStatus(status entity.ScanStatus) string {
	switch status {
	case entity.StatusCompleted:
		return color.GreenString(string(status))
	case entity.StatusFailed:
		return color.RedString(string(status))
	case entity.StatusRunning:
		return color.YellowString(string(status))
	default:
		return string(status)
	}
}

func (r *ConsoleReporter) getSeverityColor(severity entity.Severity) *color.Color {
	switch severity {
	case entity.SeverityCritical:
		return color.New(color.FgRed, color.Bold)
	case entity.SeverityHigh:
		return color.New(color.FgHiRed)
	case entity.SeverityMedium:
		return color.New(color.FgYellow)
	case entity.SeverityLow:
		return color.New(color.FgBlue)
	default:
		return color.New(color.FgWhite)
	}
}

func (r *ConsoleReporter) groupByCategory(findings []*entity.Finding) map[entity.FindingCategory][]*entity.Finding {
	grouped := make(map[entity.FindingCategory][]*entity.Finding)
	for _, f := range findings {
		grouped[f.Category] = append(grouped[f.Category], f)
	}
	return grouped
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
