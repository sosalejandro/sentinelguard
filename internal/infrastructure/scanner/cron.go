package scanner

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type CronScanner struct {
	BaseScanner
}

func NewCronScanner() *CronScanner {
	return &CronScanner{
		BaseScanner: NewBaseScanner("cron", "Scans cron jobs and scheduled tasks for suspicious entries"),
	}
}

func (s *CronScanner) Category() entity.FindingCategory {
	return entity.CategoryCron
}

func (s *CronScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting cron scan")

	var findings []*entity.Finding

	userCronFindings := s.scanUserCrontab(ctx)
	findings = append(findings, userCronFindings...)

	systemCronFindings := s.scanSystemCron(ctx)
	findings = append(findings, systemCronFindings...)

	cronDirFindings := s.scanCronDirectories(ctx)
	findings = append(findings, cronDirFindings...)

	timerFindings := s.scanSystemdTimers(ctx)
	findings = append(findings, timerFindings...)

	s.Logger().Debug("cron scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *CronScanner) scanUserCrontab(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning user crontab")

	lines, err := s.RunCommand(ctx, "crontab", "-l")
	if err != nil {
		s.Logger().Debug("no user crontab or error reading", zap.Error(err))
		return nil
	}

	return s.analyzeCronLines(lines, "user crontab")
}

func (s *CronScanner) scanSystemCron(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning system crontab")

	lines, err := s.ReadFile(ctx, "/etc/crontab")
	if err != nil {
		return nil
	}

	return s.analyzeCronLines(lines, "/etc/crontab")
}

func (s *CronScanner) scanCronDirectories(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning cron directories")

	var findings []*entity.Finding
	cronDirs := []string{
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
	}

	for _, dir := range cronDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}

			path := filepath.Join(dir, entry.Name())

			// Check if file is managed by package manager (dpkg/rpm)
			// Package-managed cron jobs are generally trusted
			isManaged := s.isPackageManaged(ctx, path)

			lines, err := s.ReadFile(ctx, path)
			if err != nil {
				continue
			}

			// For package-managed files, only check for CRITICAL patterns
			// (download & execute, reverse shells)
			if isManaged {
				dirFindings := s.analyzeCronLinesCriticalOnly(lines, path)
				findings = append(findings, dirFindings...)
			} else {
				// For unmanaged files, check everything
				dirFindings := s.analyzeCronLines(lines, path)
				findings = append(findings, dirFindings...)

				// Also flag unmanaged cron job itself as suspicious
				finding := entity.NewFinding(
					entity.CategoryCron,
					entity.SeverityMedium,
					"Non-package-managed cron job",
					"Cron job is not managed by package manager",
				).WithPath(path).
					WithDetail("managed", false)
				findings = append(findings, finding)
			}

			info, err := entry.Info()
			if err == nil {
				if info.Mode()&0002 != 0 {
					finding := entity.NewFinding(
						entity.CategoryCron,
						entity.SeverityHigh,
						"World-writable cron file",
						"Cron file is writable by any user",
					).WithPath(path).
						WithDetail("permissions", info.Mode().String())
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

// isPackageManaged checks if a file is managed by dpkg or rpm
func (s *CronScanner) isPackageManaged(ctx context.Context, path string) bool {
	// Try dpkg -S (Debian/Ubuntu)
	_, err := s.RunCommand(ctx, "dpkg", "-S", path)
	if err == nil {
		return true
	}

	// Try rpm -qf (RHEL/CentOS)
	_, err = s.RunCommand(ctx, "rpm", "-qf", path)
	if err == nil {
		return true
	}

	return false
}

// analyzeCronLinesCriticalOnly only checks for critical patterns
// Used for package-managed cron jobs where LOW/MEDIUM patterns are expected
func (s *CronScanner) analyzeCronLinesCriticalOnly(lines []string, source string) []*entity.Finding {
	var findings []*entity.Finding

	criticalPatterns := []struct {
		pattern *regexp.Regexp
		reason  string
	}{
		{
			pattern: regexp.MustCompile(`curl.*\|.*sh|wget.*\|.*sh|curl.*\|.*bash|wget.*\|.*bash`),
			reason:  "Download and execute pattern in cron job",
		},
		{
			pattern: regexp.MustCompile(`nc\s+-|ncat\s+-|netcat\s+-`),
			reason:  "Netcat in cron job",
		},
	}

	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}

		for _, sp := range criticalPatterns {
			if sp.pattern.MatchString(line) {
				finding := entity.NewFinding(
					entity.CategoryCron,
					entity.SeverityCritical,
					"Critical pattern in cron job",
					sp.reason,
				).WithPath(source).
					WithDetail("cron_line", line)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (s *CronScanner) scanSystemdTimers(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning systemd timers")

	lines, err := s.RunCommand(ctx, "systemctl", "list-timers", "--all", "--no-pager")
	if err != nil {
		return nil
	}

	var findings []*entity.Finding
	for _, line := range lines {
		if strings.Contains(line, "/tmp/") || strings.Contains(line, "/dev/shm/") {
			finding := entity.NewFinding(
				entity.CategoryCron,
				entity.SeverityHigh,
				"Systemd timer referencing temp directory",
				"Timer unit references temporary directory",
			).WithDetail("timer_line", line)
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *CronScanner) analyzeCronLines(lines []string, source string) []*entity.Finding {
	var findings []*entity.Finding

	suspiciousPatterns := []struct {
		pattern  *regexp.Regexp
		severity entity.Severity
		reason   string
	}{
		{
			pattern:  regexp.MustCompile(`curl.*\|.*sh|wget.*\|.*sh|curl.*\|.*bash|wget.*\|.*bash`),
			severity: entity.SeverityCritical,
			reason:   "Download and execute pattern in cron job",
		},
		{
			pattern:  regexp.MustCompile(`/tmp/|/var/tmp/|/dev/shm/`),
			severity: entity.SeverityMedium,
			reason:   "Cron job references temp directory",
		},
		{
			pattern:  regexp.MustCompile(`base64.*-d|base64.*--decode`),
			severity: entity.SeverityHigh,
			reason:   "Base64 decode in cron job",
		},
		{
			pattern:  regexp.MustCompile(`nc\s+-|ncat\s+-|netcat\s+-`),
			severity: entity.SeverityCritical,
			reason:   "Netcat in cron job",
		},
		{
			pattern:  regexp.MustCompile(`python.*-c|perl.*-e|ruby.*-e`),
			severity: entity.SeverityMedium,
			reason:   "Inline script execution in cron job",
		},
		{
			pattern:  regexp.MustCompile(`chmod\s+777|chmod\s+\+x.*&&.*exec`),
			severity: entity.SeverityMedium,
			reason:   "Permission change pattern in cron job",
		},
		{
			pattern:  regexp.MustCompile(`\$\(.*\)|` + "`" + `.*` + "`"),
			severity: entity.SeverityLow,
			reason:   "Command substitution in cron job",
		},
	}

	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}

		for _, sp := range suspiciousPatterns {
			if sp.pattern.MatchString(line) {
				s.Logger().Debug("suspicious cron entry found",
					zap.String("source", source),
					zap.String("line", line),
				)

				finding := entity.NewFinding(
					entity.CategoryCron,
					sp.severity,
					"Suspicious cron entry",
					sp.reason,
				).WithPath(source).
					WithDetail("cron_line", line).
					WithDetail("pattern", sp.pattern.String())
				findings = append(findings, finding)
			}
		}
	}

	return findings
}
