package scanner

import (
	"context"
	"regexp"
	"runtime"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type ProcessScanner struct {
	BaseScanner
}

func NewProcessScanner() *ProcessScanner {
	return &ProcessScanner{
		BaseScanner: NewBaseScanner("process", "Scans for suspicious running processes"),
	}
}

func (s *ProcessScanner) Category() entity.FindingCategory {
	return entity.CategoryProcess
}

// Suspicious process patterns (cross-platform)
var suspiciousProcessPatterns = []struct {
	pattern  *regexp.Regexp
	severity entity.Severity
	reason   string
}{
	// Reverse shells
	{
		pattern:  regexp.MustCompile(`nc\s+-[el]|ncat\s+-[el]|netcat\s+-[el]`),
		severity: entity.SeverityCritical,
		reason:   "Netcat listener detected - potential reverse shell",
	},
	{
		pattern:  regexp.MustCompile(`/dev/tcp/|/dev/udp/`),
		severity: entity.SeverityCritical,
		reason:   "Bash network redirection - potential reverse shell",
	},
	{
		pattern:  regexp.MustCompile(`python.*-c.*import.*socket|python.*-c.*pty\.spawn`),
		severity: entity.SeverityCritical,
		reason:   "Python reverse shell pattern detected",
	},
	{
		pattern:  regexp.MustCompile(`perl.*-e.*socket|ruby.*-rsocket`),
		severity: entity.SeverityCritical,
		reason:   "Script-based reverse shell detected",
	},
	{
		pattern:  regexp.MustCompile(`socat.*TCP|socat.*EXEC`),
		severity: entity.SeverityHigh,
		reason:   "Socat tunnel detected",
	},
	// Hidden files/directories
	{
		pattern:  regexp.MustCompile(`/tmp/\..*|/dev/shm/\..*`),
		severity: entity.SeverityHigh,
		reason:   "Process running from hidden file in temp directory",
	},
	// Download and execute
	{
		pattern:  regexp.MustCompile(`curl.*\|.*sh|wget.*\|.*sh|curl.*\|.*bash|wget.*\|.*bash`),
		severity: entity.SeverityCritical,
		reason:   "Download and execute pattern detected",
	},
	{
		pattern:  regexp.MustCompile(`base64\s+-d.*\|.*sh|base64\s+--decode.*\|.*bash`),
		severity: entity.SeverityCritical,
		reason:   "Base64 decode and execute pattern",
	},
	// Cryptocurrency miners
	{
		pattern:  regexp.MustCompile(`(?i)cryptominer|xmrig|minerd|cpuminer|ethminer|cgminer|bfgminer`),
		severity: entity.SeverityHigh,
		reason:   "Cryptocurrency miner detected",
	},
	// Process masquerading
	{
		pattern:  regexp.MustCompile(`\[kworker/.*\].*-bash|\[.*\].*python`),
		severity: entity.SeverityCritical,
		reason:   "Process masquerading as kernel thread",
	},
	// PowerShell abuse (cross-platform)
	{
		pattern:  regexp.MustCompile(`(?i)powershell.*-enc|pwsh.*-enc`),
		severity: entity.SeverityCritical,
		reason:   "Encoded PowerShell command",
	},
	{
		pattern:  regexp.MustCompile(`(?i)powershell.*downloadstring|pwsh.*downloadstring`),
		severity: entity.SeverityCritical,
		reason:   "PowerShell download cradle",
	},
	{
		pattern:  regexp.MustCompile(`(?i)powershell.*-w\s*hidden`),
		severity: entity.SeverityHigh,
		reason:   "Hidden PowerShell window",
	},
}

func (s *ProcessScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting process scan")

	var findings []*entity.Finding

	if runtime.GOOS == "windows" {
		findings = s.scanWindows(ctx)
	} else {
		findings = s.scanUnix(ctx)
	}

	s.Logger().Debug("process scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *ProcessScanner) scanUnix(ctx context.Context) []*entity.Finding {
	lines, err := s.RunCommand(ctx, "ps", "auxf")
	if err != nil {
		// Try without forest view if auxf fails (macOS)
		lines, err = s.RunCommand(ctx, "ps", "aux")
		if err != nil {
			s.Logger().Debug("failed to get process list", zap.Error(err))
			return nil
		}
	}

	return s.analyzeProcesses(lines, false)
}

func (s *ProcessScanner) scanWindows(ctx context.Context) []*entity.Finding {
	// Use tasklist with verbose output
	lines, err := s.RunCommand(ctx, "tasklist", "/v", "/fo", "csv")
	if err != nil {
		s.Logger().Debug("failed to get process list", zap.Error(err))
		return nil
	}

	findings := s.analyzeProcesses(lines, true)

	// Also get command lines via WMIC or PowerShell
	cmdLines := s.getWindowsCommandLines(ctx)
	if cmdLines != nil {
		cmdFindings := s.analyzeCommandLines(cmdLines)
		findings = append(findings, cmdFindings...)
	}

	return findings
}

func (s *ProcessScanner) getWindowsCommandLines(ctx context.Context) []string {
	// Try PowerShell first
	output, err := s.ExecCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command",
		"Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine | Format-List")
	if err == nil && output != "" {
		return strings.Split(output, "\n")
	}

	// Fallback to WMIC
	output, err = s.ExecCommand(ctx, "wmic", "process", "get", "ProcessId,Name,CommandLine", "/format:list")
	if err == nil && output != "" {
		return strings.Split(output, "\n")
	}

	return nil
}

func (s *ProcessScanner) analyzeProcesses(lines []string, isWindows bool) []*entity.Finding {
	var findings []*entity.Finding

	for _, line := range lines {
		// Skip headers
		if isWindows && (strings.HasPrefix(line, "\"Image Name\"") || strings.TrimSpace(line) == "") {
			continue
		}

		for _, sp := range suspiciousProcessPatterns {
			if sp.pattern.MatchString(line) {
				s.Logger().Debug("suspicious process found",
					zap.String("pattern", sp.pattern.String()),
					zap.String("line", line),
				)

				finding := entity.NewFinding(
					entity.CategoryProcess,
					sp.severity,
					"Suspicious process detected",
					sp.reason,
				).WithDetail("process_line", line).
					WithDetail("pattern", sp.pattern.String())
				findings = append(findings, finding)
			}
		}

		// Check for deleted executable (Unix only)
		if !isWindows && s.isDeletedExecutable(line) {
			finding := entity.NewFinding(
				entity.CategoryProcess,
				entity.SeverityHigh,
				"Process running from deleted executable",
				"A running process's executable has been deleted from disk",
			).WithDetail("process_line", line)
			findings = append(findings, finding)
		}

		// Check for suspicious process paths (Windows)
		if isWindows {
			if f := s.checkWindowsSuspiciousPath(line); f != nil {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

func (s *ProcessScanner) analyzeCommandLines(lines []string) []*entity.Finding {
	var findings []*entity.Finding
	var currentPID, currentName, currentCmdLine string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "ProcessId") {
			currentPID = strings.TrimPrefix(line, "ProcessId")
			currentPID = strings.TrimPrefix(strings.TrimSpace(currentPID), ":")
			currentPID = strings.TrimSpace(currentPID)
		} else if strings.HasPrefix(line, "Name") {
			currentName = strings.TrimPrefix(line, "Name")
			currentName = strings.TrimPrefix(strings.TrimSpace(currentName), ":")
			currentName = strings.TrimSpace(currentName)
		} else if strings.HasPrefix(line, "CommandLine") {
			currentCmdLine = strings.TrimPrefix(line, "CommandLine")
			currentCmdLine = strings.TrimPrefix(strings.TrimSpace(currentCmdLine), ":")
			currentCmdLine = strings.TrimSpace(currentCmdLine)

			// Check command line patterns
			for _, sp := range suspiciousProcessPatterns {
				if sp.pattern.MatchString(currentCmdLine) {
					finding := entity.NewFinding(
						entity.CategoryProcess,
						sp.severity,
						"Suspicious command line detected",
						sp.reason,
					).WithDetail("pid", currentPID).
						WithDetail("name", currentName).
						WithDetail("commandline", currentCmdLine).
						WithDetail("pattern", sp.pattern.String())
					findings = append(findings, finding)
					break
				}
			}

			// Reset for next process
			currentPID, currentName, currentCmdLine = "", "", ""
		}
	}

	return findings
}

func (s *ProcessScanner) checkWindowsSuspiciousPath(line string) *entity.Finding {
	suspiciousPaths := []string{
		`\temp\`,
		`\tmp\`,
		`\appdata\local\temp`,
		`\users\public\`,
		`\programdata\`,
		`\windows\temp\`,
		`\recycler\`,
		`\$recycle.bin\`,
		`\perflogs\`,
	}

	lineLower := strings.ToLower(line)
	for _, susPath := range suspiciousPaths {
		if strings.Contains(lineLower, susPath) && strings.Contains(lineLower, ".exe") {
			return entity.NewFinding(
				entity.CategoryProcess,
				entity.SeverityMedium,
				"Process running from suspicious location",
				"Executable running from "+susPath,
			).WithDetail("process_line", line).
				WithDetail("suspicious_path", susPath)
		}
	}
	return nil
}

func (s *ProcessScanner) isDeletedExecutable(line string) bool {
	return strings.Contains(line, "(deleted)") &&
		!strings.Contains(line, "vim") &&
		!strings.Contains(line, "chrome") &&
		!strings.Contains(line, "firefox") &&
		!strings.Contains(line, "electron")
}

// Windows-specific process patterns for additional detection
var windowsSpecificPatterns = []struct {
	pattern  *regexp.Regexp
	severity entity.Severity
	reason   string
}{
	{
		pattern:  regexp.MustCompile(`(?i)mshta.*vbscript|mshta.*javascript`),
		severity: entity.SeverityCritical,
		reason:   "MSHTA script execution",
	},
	{
		pattern:  regexp.MustCompile(`(?i)regsvr32.*/s.*/n`),
		severity: entity.SeverityCritical,
		reason:   "Regsvr32 script execution (Squiblydoo)",
	},
	{
		pattern:  regexp.MustCompile(`(?i)rundll32.*javascript|rundll32.*vbscript`),
		severity: entity.SeverityCritical,
		reason:   "Rundll32 script execution",
	},
	{
		pattern:  regexp.MustCompile(`(?i)certutil.*-urlcache`),
		severity: entity.SeverityHigh,
		reason:   "Certutil download (LOLBin abuse)",
	},
	{
		pattern:  regexp.MustCompile(`(?i)bitsadmin.*transfer`),
		severity: entity.SeverityHigh,
		reason:   "BITS transfer (LOLBin abuse)",
	},
	{
		pattern:  regexp.MustCompile(`(?i)wmic.*process.*call.*create`),
		severity: entity.SeverityHigh,
		reason:   "WMIC process creation",
	},
	{
		pattern:  regexp.MustCompile(`(?i)mimikatz|sekurlsa`),
		severity: entity.SeverityCritical,
		reason:   "Credential dumping tool detected",
	},
	{
		pattern:  regexp.MustCompile(`(?i)procdump.*lsass`),
		severity: entity.SeverityCritical,
		reason:   "LSASS memory dump attempt",
	},
}

// GetWindowsPatterns returns Windows-specific patterns for use by other scanners
func GetWindowsPatterns() []struct {
	Pattern  *regexp.Regexp
	Severity entity.Severity
	Reason   string
} {
	result := make([]struct {
		Pattern  *regexp.Regexp
		Severity entity.Severity
		Reason   string
	}, len(windowsSpecificPatterns))

	for i, p := range windowsSpecificPatterns {
		result[i] = struct {
			Pattern  *regexp.Regexp
			Severity entity.Severity
			Reason   string
		}{
			Pattern:  p.pattern,
			Severity: p.severity,
			Reason:   p.reason,
		}
	}
	return result
}
