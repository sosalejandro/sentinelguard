package scanner

import (
	"context"
	"regexp"
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

func (s *ProcessScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting process scan")

	var findings []*entity.Finding

	procFindings, err := s.scanProcesses(ctx)
	if err == nil {
		findings = append(findings, procFindings...)
	}

	s.Logger().Debug("process scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *ProcessScanner) scanProcesses(ctx context.Context) ([]*entity.Finding, error) {
	lines, err := s.RunCommand(ctx, "ps", "auxf")
	if err != nil {
		return nil, err
	}

	var findings []*entity.Finding

	suspiciousPatterns := []struct {
		pattern  *regexp.Regexp
		severity entity.Severity
		reason   string
	}{
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
		{
			pattern:  regexp.MustCompile(`/tmp/\..*|/dev/shm/\..*`),
			severity: entity.SeverityHigh,
			reason:   "Process running from hidden file in temp directory",
		},
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
		{
			pattern:  regexp.MustCompile(`cryptominer|xmrig|minerd|cpuminer`),
			severity: entity.SeverityHigh,
			reason:   "Cryptocurrency miner detected",
		},
		{
			pattern:  regexp.MustCompile(`\[kworker/.*\].*-bash|\[.*\].*python`),
			severity: entity.SeverityCritical,
			reason:   "Process masquerading as kernel thread",
		},
	}

	for _, line := range lines {
		for _, sp := range suspiciousPatterns {
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

		if s.isDeletedExecutable(line) {
			finding := entity.NewFinding(
				entity.CategoryProcess,
				entity.SeverityHigh,
				"Process running from deleted executable",
				"A running process's executable has been deleted from disk",
			).WithDetail("process_line", line)
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (s *ProcessScanner) isDeletedExecutable(line string) bool {
	return strings.Contains(line, "(deleted)") && !strings.Contains(line, "vim") && !strings.Contains(line, "chrome")
}
