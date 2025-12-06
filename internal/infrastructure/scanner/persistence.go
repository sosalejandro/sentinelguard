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

type PersistenceScanner struct {
	BaseScanner
}

func NewPersistenceScanner() *PersistenceScanner {
	return &PersistenceScanner{
		BaseScanner: NewBaseScanner("persistence", "Scans for persistence mechanisms including startup scripts and services"),
	}
}

func (s *PersistenceScanner) Category() entity.FindingCategory {
	return entity.CategoryPersistence
}

func (s *PersistenceScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting persistence scan")

	var findings []*entity.Finding

	profileFindings := s.scanProfileScripts(ctx)
	findings = append(findings, profileFindings...)

	serviceFindings := s.scanSystemdServices(ctx)
	findings = append(findings, serviceFindings...)

	ldPreloadFindings := s.scanLDPreload(ctx)
	findings = append(findings, ldPreloadFindings...)

	s.Logger().Debug("persistence scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *PersistenceScanner) scanProfileScripts(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning profile scripts")

	var findings []*entity.Finding
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	profileFiles := []string{
		filepath.Join(homeDir, ".bashrc"),
		filepath.Join(homeDir, ".bash_profile"),
		filepath.Join(homeDir, ".profile"),
		filepath.Join(homeDir, ".zshrc"),
		"/etc/profile",
		"/etc/bash.bashrc",
	}

	suspiciousPatterns := []struct {
		pattern  *regexp.Regexp
		severity entity.Severity
		reason   string
	}{
		{
			pattern:  regexp.MustCompile(`curl.*\|.*sh|wget.*\|.*sh|curl.*\|.*bash`),
			severity: entity.SeverityCritical,
			reason:   "Download and execute pattern in profile",
		},
		{
			pattern:  regexp.MustCompile(`nc\s+-[el]|ncat|/dev/tcp/`),
			severity: entity.SeverityCritical,
			reason:   "Reverse shell pattern in profile",
		},
		{
			pattern:  regexp.MustCompile(`base64.*-d.*\|`),
			severity: entity.SeverityHigh,
			reason:   "Base64 decode and pipe in profile",
		},
		{
			pattern:  regexp.MustCompile(`export\s+LD_PRELOAD=`),
			severity: entity.SeverityCritical,
			reason:   "LD_PRELOAD injection in profile",
		},
		{
			// Only flag aliases that redirect to different binaries or add suspicious behavior
			// Normal: alias ls='ls --color' | Suspicious: alias sudo='/tmp/fake_sudo'
			pattern:  regexp.MustCompile(`alias\s+(sudo|su|ssh|ps|netstat)=['"]?(/tmp/|/dev/shm/|/var/tmp/|[^'"\s]*\|)`),
			severity: entity.SeverityHigh,
			reason:   "Command alias redirected to temp path or piped",
		},
		{
			// Only flag eval patterns that look like obfuscation
			// Legitimate uses: eval "$(dircolors)", eval "$(ssh-agent)", completion setup
			pattern:  regexp.MustCompile(`eval\s+"?\$\(\s*(curl|wget|base64|nc\s|python|perl|ruby)`),
			severity: entity.SeverityHigh,
			reason:   "Suspicious eval with download/decode command",
		},
		{
			pattern:  regexp.MustCompile(`/tmp/\.[^/]+|/dev/shm/\.[^/]+`),
			severity: entity.SeverityHigh,
			reason:   "Hidden file in temp directory referenced",
		},
	}

	for _, profilePath := range profileFiles {
		if !s.FileExists(profilePath) {
			continue
		}

		lines, err := s.ReadFile(ctx, profilePath)
		if err != nil {
			continue
		}

		for lineNum, line := range lines {
			for _, sp := range suspiciousPatterns {
				if sp.pattern.MatchString(line) {
					finding := entity.NewFinding(
						entity.CategoryPersistence,
						sp.severity,
						"Suspicious entry in profile script",
						sp.reason,
					).WithPath(profilePath).
						WithDetail("line_number", lineNum+1).
						WithDetail("content", strings.TrimSpace(line))
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

func (s *PersistenceScanner) scanSystemdServices(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning systemd services")

	var findings []*entity.Finding
	serviceDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		serviceDirs = append(serviceDirs, filepath.Join(homeDir, ".config/systemd/user"))
	}

	for _, dir := range serviceDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".service") {
				continue
			}

			path := filepath.Join(dir, entry.Name())
			lines, err := s.ReadFile(ctx, path)
			if err != nil {
				continue
			}

			content := strings.Join(lines, "\n")

			if strings.Contains(content, "/tmp/") || strings.Contains(content, "/dev/shm/") {
				finding := entity.NewFinding(
					entity.CategoryPersistence,
					entity.SeverityHigh,
					"Systemd service references temp directory",
					"Service executes from temporary directory",
				).WithPath(path)
				findings = append(findings, finding)
			}

			if strings.Contains(content, "Type=oneshot") && strings.Contains(content, "RemainAfterExit=yes") {
				if strings.Contains(content, "/tmp/") || strings.Contains(content, "curl") || strings.Contains(content, "wget") {
					finding := entity.NewFinding(
						entity.CategoryPersistence,
						entity.SeverityHigh,
						"Suspicious oneshot service",
						"Oneshot service with persistence and suspicious content",
					).WithPath(path)
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings
}

func (s *PersistenceScanner) scanLDPreload(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning LD_PRELOAD")

	var findings []*entity.Finding

	if s.FileExists("/etc/ld.so.preload") {
		lines, err := s.ReadFile(ctx, "/etc/ld.so.preload")
		if err == nil && len(lines) > 0 {
			for _, line := range lines {
				if strings.TrimSpace(line) != "" && !strings.HasPrefix(line, "#") {
					finding := entity.NewFinding(
						entity.CategoryPersistence,
						entity.SeverityCritical,
						"LD_PRELOAD persistence detected",
						"Library preloading configured system-wide",
					).WithPath("/etc/ld.so.preload").
						WithDetail("library", strings.TrimSpace(line))
					findings = append(findings, finding)
				}
			}
		}
	}

	ldPreload := os.Getenv("LD_PRELOAD")
	if ldPreload != "" {
		finding := entity.NewFinding(
			entity.CategoryPersistence,
			entity.SeverityCritical,
			"LD_PRELOAD environment variable set",
			"LD_PRELOAD is set in current environment",
		).WithDetail("value", ldPreload)
		findings = append(findings, finding)
	}

	return findings
}
