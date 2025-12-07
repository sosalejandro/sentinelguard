package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// PAMScanner detects PAM-based backdoors and authentication bypasses
type PAMScanner struct {
	BaseScanner
}

// Suspicious PAM modules and configurations
var (
	// PAM modules that can be abused for backdoors
	// Note: pam_permit is handled separately - only dangerous in auth stack
	suspiciousPAMModules = map[string]string{
		"pam_exec.so":   "Executes arbitrary commands on auth",
		"pam_script.so": "Runs scripts during authentication",
		"pam_debug.so":  "Debug module that may leak credentials",
	}

	// Locations where PAM modules should exist
	pamModulePaths = []string{
		"/lib/security",
		"/lib64/security",
		"/lib/x86_64-linux-gnu/security",
		"/usr/lib/security",
		"/usr/lib64/security",
		"/usr/lib/x86_64-linux-gnu/security",
	}

	// Critical PAM config files
	criticalPAMConfigs = []string{
		"/etc/pam.d/common-auth",
		"/etc/pam.d/common-password",
		"/etc/pam.d/common-session",
		"/etc/pam.d/common-account",
		"/etc/pam.d/su",
		"/etc/pam.d/sudo",
		"/etc/pam.d/sshd",
		"/etc/pam.d/login",
		"/etc/pam.d/system-auth",
		"/etc/pam.d/password-auth",
	}

	// Known good hashes for pam_unix.so (Ubuntu/Debian)
	// In production, these should be maintained per distribution/version
	knownPAMUnixHashes = map[string]bool{
		// This would contain SHA256 hashes of legitimate pam_unix.so files
		// For now, we'll check for modifications via package manager
	}
)

func NewPAMScanner() *PAMScanner {
	return &PAMScanner{
		BaseScanner: NewBaseScanner("pam", "PAM backdoor and authentication bypass detector"),
	}
}

func (s *PAMScanner) Category() entity.FindingCategory {
	return entity.CategoryPAM
}

func (s *PAMScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting PAM scan")
	var findings []*entity.Finding

	// Check for suspicious PAM configurations
	if f := s.checkPAMConfigs(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Verify PAM module integrity
	if f := s.verifyPAMModules(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for pam_permit in unexpected places
	if f := s.checkPAMPermit(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for pam_exec abuse
	if f := s.checkPAMExec(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check PAM module path for rogue modules
	if f := s.checkRoguePAMModules(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("PAM scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *PAMScanner) checkPAMConfigs(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	pamDir := "/etc/pam.d"
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		s.log.Debug("cannot read PAM config directory", zap.Error(err))
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if entry.IsDir() {
			continue
		}

		configPath := filepath.Join(pamDir, entry.Name())
		file, err := os.Open(configPath)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(file)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())

			// Skip comments and empty lines
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Check for suspicious modules
			for module, description := range suspiciousPAMModules {
				if strings.Contains(line, module) {
					severity := entity.SeverityMedium

					// pam_permit in auth is critical
					if module == "pam_permit.so" && strings.HasPrefix(line, "auth") {
						severity = entity.SeverityCritical
					}

					// pam_exec running scripts is high severity
					if module == "pam_exec.so" {
						severity = entity.SeverityHigh
					}

					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("pam-suspicious-%s-%s-%d", entry.Name(), module, lineNum),
						Category:    "pam",
						Severity:    severity,
						Title:       "Suspicious PAM module configuration",
						Description: fmt.Sprintf("%s: %s", module, description),
						Path:        configPath,
						Details: map[string]interface{}{
							"config_file": entry.Name(),
							"line_number": lineNum,
							"line":        line,
							"module":      module,
							"risk":        description,
						},
					})
				}
			}

			// Check for "sufficient" with no follow-up required
			if strings.Contains(line, "sufficient") && strings.Contains(line, "pam_permit") {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("pam-bypass-%s-%d", entry.Name(), lineNum),
					Category:    "pam",
					Severity:    entity.SeverityCritical,
					Title:       "PAM authentication bypass detected",
					Description: "pam_permit.so with 'sufficient' allows passwordless authentication",
					Path:        configPath,
					Details: map[string]interface{}{
						"config_file": entry.Name(),
						"line_number": lineNum,
						"line":        line,
						"impact":      "Complete authentication bypass",
					},
				})
			}
		}
		file.Close()
	}

	return findings
}

func (s *PAMScanner) verifyPAMModules(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check pam_unix.so specifically as it's the most critical
	for _, basePath := range pamModulePaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		pamUnixPath := filepath.Join(basePath, "pam_unix.so")
		if _, err := os.Stat(pamUnixPath); err != nil {
			continue
		}

		// Calculate hash
		data, err := os.ReadFile(pamUnixPath)
		if err != nil {
			continue
		}

		hash := fmt.Sprintf("%x", sha256.Sum256(data))

		// In a real implementation, verify against known-good hashes
		// For now, we'll use package manager verification
		s.log.Debug("pam_unix.so found",
			zap.String("path", pamUnixPath),
			zap.String("sha256", hash),
		)

		// Check file permissions (should be 0644 or similar)
		info, err := os.Stat(pamUnixPath)
		if err == nil {
			mode := info.Mode()
			if mode&0o002 != 0 { // World writable
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("pam-worldwrite-%s", filepath.Base(pamUnixPath)),
					Category:    "pam",
					Severity:    entity.SeverityCritical,
					Title:       "PAM module is world-writable",
					Description: "Critical PAM module can be modified by any user",
					Path:        pamUnixPath,
					Details: map[string]interface{}{
						"permissions": mode.String(),
						"sha256":      hash,
					},
				})
			}
		}
	}

	return findings
}

func (s *PAMScanner) checkPAMPermit(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// pam_permit should only be used in specific scenarios
	// Check if it appears in authentication stacks where it shouldn't
	dangerousConfigs := []string{
		"/etc/pam.d/sshd",
		"/etc/pam.d/login",
		"/etc/pam.d/su",
		"/etc/pam.d/sudo",
		"/etc/pam.d/common-auth",
		"/etc/pam.d/system-auth",
	}

	for _, config := range dangerousConfigs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		data, err := os.ReadFile(config)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			// Skip comments
			if strings.HasPrefix(trimmed, "#") || trimmed == "" {
				continue
			}

			// Only check auth lines with pam_permit
			if !strings.HasPrefix(trimmed, "auth") || !strings.Contains(line, "pam_permit.so") {
				continue
			}

			// pam_permit with "sufficient" is ALWAYS dangerous - bypasses all auth
			if strings.Contains(line, "sufficient") {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("pam-permit-sufficient-%s", filepath.Base(config)),
					Category:    "pam",
					Severity:    entity.SeverityCritical,
					Title:       "pam_permit with sufficient - auth bypass",
					Description: "pam_permit.so with 'sufficient' allows passwordless login",
					Path:        config,
					Details: map[string]interface{}{
						"line_number": i + 1,
						"line":        line,
						"service":     filepath.Base(config),
						"risk":        "Complete authentication bypass",
					},
				})
				continue
			}

			// pam_permit with "required" at end of stack (after pam_deny) is NORMAL
			// This is standard PAM config to set success return code
			// Only flag if it appears BEFORE pam_unix or other auth modules
			if strings.Contains(line, "required") {
				// Check if pam_unix appears AFTER this line (that would be suspicious)
				pamUnixAfter := false
				for j := i + 1; j < len(lines); j++ {
					laterLine := strings.TrimSpace(lines[j])
					if strings.HasPrefix(laterLine, "#") || laterLine == "" {
						continue
					}
					if strings.HasPrefix(laterLine, "auth") && strings.Contains(laterLine, "pam_unix.so") {
						pamUnixAfter = true
						break
					}
				}

				if pamUnixAfter {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("pam-permit-before-auth-%s", filepath.Base(config)),
						Category:    "pam",
						Severity:    entity.SeverityCritical,
						Title:       "pam_permit before actual auth modules",
						Description: "pam_permit.so appears before pam_unix.so - potential backdoor",
						Path:        config,
						Details: map[string]interface{}{
							"line_number": i + 1,
							"line":        line,
							"service":     filepath.Base(config),
							"risk":        "Authentication bypass if pam_permit succeeds first",
						},
					})
				}
				// If pam_permit required is AFTER pam_unix, it's normal config
				continue
			}
		}
	}

	return findings
}

func (s *PAMScanner) checkPAMExec(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	pamDir := "/etc/pam.d"
	entries, err := os.ReadDir(pamDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if entry.IsDir() {
			continue
		}

		configPath := filepath.Join(pamDir, entry.Name())
		data, err := os.ReadFile(configPath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if strings.Contains(line, "pam_exec.so") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
				// Extract the executed command
				parts := strings.Split(line, "pam_exec.so")
				execCmd := ""
				if len(parts) > 1 {
					execCmd = strings.TrimSpace(parts[1])
				}

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("pam-exec-%s-%d", entry.Name(), i+1),
					Category:    "pam",
					Severity:    entity.SeverityHigh,
					Title:       "PAM command execution configured",
					Description: "pam_exec.so runs commands during authentication - verify legitimacy",
					Path:        configPath,
					Details: map[string]interface{}{
						"service":     entry.Name(),
						"line_number": i + 1,
						"line":        line,
						"command":     execCmd,
						"risk":        "Can be used to run backdoor on every login",
					},
				})
			}
		}
	}

	return findings
}

func (s *PAMScanner) checkRoguePAMModules(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	for _, basePath := range pamModulePaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}

		entries, err := os.ReadDir(basePath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".so") {
				continue
			}

			modulePath := filepath.Join(basePath, entry.Name())
			info, err := entry.Info()
			if err != nil {
				continue
			}

			// Check for recently modified PAM modules (potential tampering)
			// In WSL2/containers, this might trigger false positives
			modTime := info.ModTime()

			// Check file permissions
			mode := info.Mode()
			if mode&0o002 != 0 { // World writable
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("pam-module-worldwrite-%s", entry.Name()),
					Category:    "pam",
					Severity:    entity.SeverityCritical,
					Title:       "World-writable PAM module",
					Description: fmt.Sprintf("PAM module %s is world-writable", entry.Name()),
					Path:        modulePath,
					Details: map[string]interface{}{
						"module":      entry.Name(),
						"permissions": mode.String(),
						"modified":    modTime.String(),
					},
				})
			}

			// Check for modules not owned by root
			// Note: This requires syscall for proper UID check
			// Simplified check using os.Stat
		}
	}

	return findings
}
