package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type SSHScanner struct {
	BaseScanner
}

func NewSSHScanner() *SSHScanner {
	return &SSHScanner{
		BaseScanner: NewBaseScanner("ssh", "Scans SSH configuration and authorized keys for anomalies"),
	}
}

func (s *SSHScanner) Category() entity.FindingCategory {
	return entity.CategorySSH
}

func (s *SSHScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting SSH scan")

	var findings []*entity.Finding

	authKeyFindings := s.scanAuthorizedKeys(ctx)
	findings = append(findings, authKeyFindings...)

	configFindings := s.scanSSHConfig(ctx)
	findings = append(findings, configFindings...)

	s.Logger().Debug("SSH scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *SSHScanner) scanAuthorizedKeys(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning authorized_keys files")

	var findings []*entity.Finding
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil
	}

	authKeysPath := filepath.Join(homeDir, ".ssh", "authorized_keys")
	if !s.FileExists(authKeysPath) {
		s.Logger().Debug("no authorized_keys file found")
		return nil
	}

	lines, err := s.ReadFile(ctx, authKeysPath)
	if err != nil {
		return nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s.Logger().Debug("found authorized key", zap.String("key_preview", truncateKey(line)))

		if strings.Contains(line, "command=") {
			cmd := extractCommand(line)
			finding := entity.NewFinding(
				entity.CategorySSH,
				entity.SeverityHigh,
				"SSH key with forced command",
				"An SSH key has a forced command configured",
			).WithPath(authKeysPath).
				WithDetail("command", cmd)
			findings = append(findings, finding)
		}

		if strings.Contains(line, "no-pty") || strings.Contains(line, "no-agent-forwarding") {
			finding := entity.NewFinding(
				entity.CategorySSH,
				entity.SeverityInfo,
				"SSH key with restrictions",
				"SSH key has security restrictions configured",
			).WithPath(authKeysPath).
				WithDetail("restrictions", extractRestrictions(line))
			findings = append(findings, finding)
		}

		if !strings.Contains(line, "@") && !strings.Contains(line, " ") {
			finding := entity.NewFinding(
				entity.CategorySSH,
				entity.SeverityMedium,
				"SSH key without comment/identifier",
				"SSH key has no identifying comment - may be unauthorized",
			).WithPath(authKeysPath)
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *SSHScanner) scanSSHConfig(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning SSH config")

	var findings []*entity.Finding

	sshdConfigPath := "/etc/ssh/sshd_config"
	lines, err := s.ReadFile(ctx, sshdConfigPath)
	if err != nil {
		return nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		lowerLine := strings.ToLower(line)

		if strings.HasPrefix(lowerLine, "permitrootlogin") && strings.Contains(lowerLine, "yes") {
			finding := entity.NewFinding(
				entity.CategorySSH,
				entity.SeverityMedium,
				"SSH root login enabled",
				"Root login via SSH is permitted",
			).WithPath(sshdConfigPath).
				WithDetail("config_line", line)
			findings = append(findings, finding)
		}

		if strings.HasPrefix(lowerLine, "passwordauthentication") && strings.Contains(lowerLine, "yes") {
			finding := entity.NewFinding(
				entity.CategorySSH,
				entity.SeverityLow,
				"SSH password authentication enabled",
				"Password authentication is enabled (key-only is more secure)",
			).WithPath(sshdConfigPath).
				WithDetail("config_line", line)
			findings = append(findings, finding)
		}

		if strings.HasPrefix(lowerLine, "permitemptypasswords") && strings.Contains(lowerLine, "yes") {
			finding := entity.NewFinding(
				entity.CategorySSH,
				entity.SeverityCritical,
				"SSH empty passwords permitted",
				"Empty passwords are allowed for SSH login",
			).WithPath(sshdConfigPath).
				WithDetail("config_line", line)
			findings = append(findings, finding)
		}
	}

	return findings
}

func truncateKey(key string) string {
	if len(key) > 50 {
		return key[:50] + "..."
	}
	return key
}

func extractCommand(line string) string {
	start := strings.Index(line, "command=\"")
	if start == -1 {
		return ""
	}
	start += 9
	end := strings.Index(line[start:], "\"")
	if end == -1 {
		return ""
	}
	return line[start : start+end]
}

func extractRestrictions(line string) string {
	var restrictions []string
	if strings.Contains(line, "no-pty") {
		restrictions = append(restrictions, "no-pty")
	}
	if strings.Contains(line, "no-agent-forwarding") {
		restrictions = append(restrictions, "no-agent-forwarding")
	}
	if strings.Contains(line, "no-X11-forwarding") {
		restrictions = append(restrictions, "no-X11-forwarding")
	}
	if strings.Contains(line, "no-port-forwarding") {
		restrictions = append(restrictions, "no-port-forwarding")
	}
	return strings.Join(restrictions, ", ")
}
