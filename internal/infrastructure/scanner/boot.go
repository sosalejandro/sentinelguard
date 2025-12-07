package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// BootScanner detects boot-time persistence mechanisms
type BootScanner struct {
	BaseScanner
}

// Suspicious patterns in boot scripts
var (
	bootSuspiciousPatterns = []string{
		"curl",
		"wget",
		"nc ",
		"netcat",
		"ncat",
		"/dev/tcp",
		"/dev/udp",
		"base64",
		"eval",
		"python -c",
		"perl -e",
		"ruby -e",
		"bash -i",
		"exec ",
		"nohup",
		"screen -d",
		"tmux new",
	}

	// Init systems to check
	initPaths = []string{
		"/etc/rc.local",
		"/etc/rc.d/rc.local",
	}

	// Init.d directory
	initDDirs = []string{
		"/etc/init.d",
		"/etc/rc.d/init.d",
	}
)

func NewBootScanner() *BootScanner {
	return &BootScanner{
		BaseScanner: NewBaseScanner("boot", "Boot-time persistence and startup script scanner"),
	}
}

func (s *BootScanner) Category() entity.FindingCategory {
	return entity.CategoryBoot
}

func (s *BootScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting boot persistence scan")
	var findings []*entity.Finding

	// Check rc.local
	if f := s.checkRcLocal(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check init.d scripts
	if f := s.checkInitD(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check GRUB configuration
	if f := s.checkGrub(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check initramfs for modifications (basic check)
	if f := s.checkInitramfs(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check systemd generators (can run at boot)
	if f := s.checkSystemdGenerators(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check kernel boot parameters
	if f := s.checkKernelParams(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("boot scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *BootScanner) checkRcLocal(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	for _, rcPath := range initPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		info, err := os.Stat(rcPath)
		if err != nil {
			continue
		}

		// Check if rc.local is executable (active)
		isExecutable := info.Mode()&0o111 != 0

		data, err := os.ReadFile(rcPath)
		if err != nil {
			continue
		}

		content := string(data)
		lines := strings.Split(content, "\n")

		hasContent := false
		for lineNum, line := range lines {
			line = strings.TrimSpace(line)

			// Skip empty lines, comments, and shebang
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Skip "exit 0" as it's standard
			if line == "exit 0" {
				continue
			}

			hasContent = true

			// Check for suspicious patterns
			for _, pattern := range bootSuspiciousPatterns {
				if strings.Contains(strings.ToLower(line), pattern) {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("boot-rclocal-sus-%d", lineNum+1),
						Category:    "boot",
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious command in rc.local",
						Description: fmt.Sprintf("rc.local contains suspicious pattern: %s", pattern),
						Path:        rcPath,
						Details: map[string]interface{}{
							"line_number":  lineNum + 1,
							"line":         line,
							"pattern":      pattern,
							"is_executable": isExecutable,
						},
					})
					break
				}
			}
		}

		// Report if rc.local has custom content (unusual on modern systems)
		if hasContent && isExecutable {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("boot-rclocal-active-%s", filepath.Base(rcPath)),
				Category:    "boot",
				Severity:    entity.SeverityMedium,
				Title:       "Active rc.local with custom content",
				Description: "rc.local is executable and contains custom commands",
				Path:        rcPath,
				Details: map[string]interface{}{
					"is_executable": true,
					"note":          "Modern systems typically use systemd, rc.local is legacy",
				},
			})
		}
	}

	return findings
}

func (s *BootScanner) checkInitD(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	for _, initDir := range initDDirs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := os.ReadDir(initDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			scriptPath := filepath.Join(initDir, entry.Name())

			// Check if it's a dpkg/rpm managed file
			isManaged := s.isPackageManaged(ctx, scriptPath)

			if !isManaged {
				// Non-package managed init script is suspicious
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("boot-initd-unmanaged-%s", entry.Name()),
					Category:    "boot",
					Severity:    entity.SeverityMedium,
					Title:       "Non-package-managed init script",
					Description: fmt.Sprintf("Init script '%s' is not managed by package manager", entry.Name()),
					Path:        scriptPath,
					Details: map[string]interface{}{
						"script":     entry.Name(),
						"is_managed": false,
						"risk":       "Could be manually added backdoor",
					},
				})

				// Only scan content of UNMANAGED scripts for suspicious patterns
				// Package-managed scripts legitimately use exec, nohup, etc.
				data, err := os.ReadFile(scriptPath)
				if err != nil {
					continue
				}

				lines := strings.Split(string(data), "\n")
				for lineNum, line := range lines {
					lineLower := strings.ToLower(line)

					// More restrictive patterns for unmanaged scripts
					dangerousPatterns := []string{"curl", "wget", "/dev/tcp", "/dev/udp", "base64", "nc ", "netcat", "ncat"}
					for _, pattern := range dangerousPatterns {
						if strings.Contains(lineLower, pattern) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
							findings = append(findings, &entity.Finding{
								ID:          fmt.Sprintf("boot-initd-sus-%s-%d", entry.Name(), lineNum+1),
								Category:    "boot",
								Severity:    entity.SeverityHigh,
								Title:       "Suspicious command in unmanaged init script",
								Description: fmt.Sprintf("Unmanaged init script '%s' contains suspicious pattern", entry.Name()),
								Path:        scriptPath,
								Details: map[string]interface{}{
									"script":      entry.Name(),
									"line_number": lineNum + 1,
									"line":        line,
									"pattern":     pattern,
								},
							})
							break
						}
					}
				}
			}
		}
	}

	return findings
}

func (s *BootScanner) isPackageManaged(ctx context.Context, path string) bool {
	// Try dpkg -S (Debian/Ubuntu)
	_, err := s.ExecCommand(ctx, "dpkg", "-S", path)
	if err == nil {
		return true
	}

	// Try rpm -qf (RHEL/CentOS)
	_, err = s.ExecCommand(ctx, "rpm", "-qf", path)
	return err == nil
}

func (s *BootScanner) checkGrub(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	grubPaths := []string{
		"/boot/grub/grub.cfg",
		"/boot/grub2/grub.cfg",
		"/etc/default/grub",
	}

	for _, grubPath := range grubPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		data, err := os.ReadFile(grubPath)
		if err != nil {
			continue
		}

		content := string(data)

		// Check for suspicious kernel parameters
		suspiciousParams := []string{
			"init=/",           // Custom init (could be backdoor)
			"single",           // Single user mode
			"emergency",        // Emergency mode
			"rd.break",         // Break into initramfs
			"rdinit=",          // Custom ramdisk init
			"rootflags=",       // Could mount with special flags
		}

		for _, param := range suspiciousParams {
			if strings.Contains(content, param) {
				// Don't flag init=/sbin/init or init=/lib/systemd/systemd
				if param == "init=/" {
					if strings.Contains(content, "init=/sbin/init") ||
						strings.Contains(content, "init=/lib/systemd/systemd") ||
						strings.Contains(content, "init=/usr/lib/systemd/systemd") {
						continue
					}
				}

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("boot-grub-%s", strings.ReplaceAll(param, "/", "")),
					Category:    "boot",
					Severity:    entity.SeverityMedium,
					Title:       "Suspicious GRUB configuration",
					Description: fmt.Sprintf("GRUB config contains potentially dangerous parameter: %s", param),
					Path:        grubPath,
					Details: map[string]interface{}{
						"parameter": param,
						"risk":      "Could allow boot-time compromise or recovery bypass",
					},
				})
			}
		}

		// Check grub.cfg permissions
		info, err := os.Stat(grubPath)
		if err == nil {
			if info.Mode()&0o002 != 0 {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("boot-grub-worldwrite-%s", filepath.Base(grubPath)),
					Category:    "boot",
					Severity:    entity.SeverityCritical,
					Title:       "World-writable GRUB configuration",
					Description: "GRUB configuration is world-writable",
					Path:        grubPath,
					Details: map[string]interface{}{
						"permissions": info.Mode().String(),
					},
				})
			}
		}
	}

	return findings
}

func (s *BootScanner) checkInitramfs(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check /boot for initramfs files
	bootDir := "/boot"
	entries, err := os.ReadDir(bootDir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		name := entry.Name()

		// Look for initramfs/initrd files
		if !strings.HasPrefix(name, "initramfs") && !strings.HasPrefix(name, "initrd") {
			continue
		}

		initPath := filepath.Join(bootDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Check for world-writable initramfs (critical!)
		if info.Mode()&0o002 != 0 {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("boot-initramfs-worldwrite-%s", name),
				Category:    "boot",
				Severity:    entity.SeverityCritical,
				Title:       "World-writable initramfs",
				Description: fmt.Sprintf("Initramfs '%s' is world-writable", name),
				Path:        initPath,
				Details: map[string]interface{}{
					"permissions": info.Mode().String(),
					"risk":        "Complete boot-time compromise possible",
				},
			})
		}

		// Log modification time for reference
		s.log.Debug("initramfs found",
			zap.String("path", initPath),
			zap.Time("modified", info.ModTime()),
			zap.Int64("size", info.Size()),
		)
	}

	return findings
}

func (s *BootScanner) checkSystemdGenerators(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Systemd generator directories
	generatorDirs := []string{
		"/etc/systemd/system-generators",
		"/usr/local/lib/systemd/system-generators",
		"/run/systemd/system-generators",
	}

	for _, genDir := range generatorDirs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := os.ReadDir(genDir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			genPath := filepath.Join(genDir, entry.Name())

			// Check if it's package managed
			isManaged := s.isPackageManaged(ctx, genPath)

			if !isManaged {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("boot-generator-%s", entry.Name()),
					Category:    "boot",
					Severity:    entity.SeverityHigh,
					Title:       "Non-package-managed systemd generator",
					Description: fmt.Sprintf("Systemd generator '%s' is not managed by package manager", entry.Name()),
					Path:        genPath,
					Details: map[string]interface{}{
						"generator":  entry.Name(),
						"directory":  genDir,
						"is_managed": false,
						"risk":       "Generators run early at boot, before most security controls",
					},
				})
			}
		}
	}

	return findings
}

func (s *BootScanner) checkKernelParams(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Read current kernel command line
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return nil
	}

	params := string(cmdline)

	// Check if running in WSL (debug is common in WSL kernels)
	isWSL := strings.Contains(params, "WSL") ||
		strings.Contains(params, "microsoft") ||
		s.FileExists("/proc/sys/fs/binfmt_misc/WSLInterop")

	// Suspicious runtime parameters
	// Note: Some parameters are less suspicious in WSL/container environments
	suspiciousRuntimeParams := []string{
		"init=/bin/",  // Custom init shell
		"init=/tmp/",  // Init from temp
		"single",      // Single user mode (if running)
		"emergency",   // Emergency mode
		"rd.break",    // Initramfs break
		"selinux=0",   // SELinux disabled
		"apparmor=0",  // AppArmor disabled
		"enforcing=0", // SELinux permissive
	}

	// Don't flag debug parameter in WSL - it's normal
	if !isWSL {
		suspiciousRuntimeParams = append(suspiciousRuntimeParams, "debug")
	}

	for _, param := range suspiciousRuntimeParams {
		if strings.Contains(params, param) {
			severity := entity.SeverityMedium
			if strings.Contains(param, "init=") {
				severity = entity.SeverityHigh
			}

			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("boot-cmdline-%s", strings.ReplaceAll(param, "/", "")),
				Category:    "boot",
				Severity:    severity,
				Title:       "Suspicious kernel boot parameter",
				Description: fmt.Sprintf("System booted with suspicious parameter: %s", param),
				Path:        "/proc/cmdline",
				Details: map[string]interface{}{
					"parameter":    param,
					"full_cmdline": params,
				},
			})
		}
	}

	return findings
}
