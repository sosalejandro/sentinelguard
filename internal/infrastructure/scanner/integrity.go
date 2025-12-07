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

// IntegrityScanner verifies system binary integrity and detects tampering
type IntegrityScanner struct {
	BaseScanner
}

// Critical system binaries that should be verified
var criticalBinaries = []string{
	// Core utilities
	"/bin/ls", "/bin/ps", "/bin/netstat", "/bin/ss", "/bin/top",
	"/bin/login", "/bin/su", "/bin/passwd", "/bin/bash", "/bin/sh",
	"/usr/bin/ls", "/usr/bin/ps", "/usr/bin/netstat", "/usr/bin/ss", "/usr/bin/top",
	"/usr/bin/login", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/bash", "/usr/bin/sh",
	"/usr/bin/sudo", "/usr/bin/ssh", "/usr/bin/sshd", "/usr/bin/crontab",

	// System utilities
	"/sbin/init", "/sbin/modprobe", "/sbin/insmod", "/sbin/rmmod",
	"/usr/sbin/sshd", "/usr/sbin/cron", "/usr/sbin/crond",

	// Dynamic linker (critical for LD_PRELOAD attacks)
	"/lib/ld-linux.so.2",
	"/lib64/ld-linux-x86-64.so.2",
	"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
}

func NewIntegrityScanner() *IntegrityScanner {
	return &IntegrityScanner{
		BaseScanner: NewBaseScanner("integrity", "System binary integrity and package verification scanner"),
	}
}

func (s *IntegrityScanner) Category() entity.FindingCategory {
	return entity.CategoryIntegrity
}

func (s *IntegrityScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting integrity scan")
	var findings []*entity.Finding

	// Check package manager verification (dpkg -V for Debian/Ubuntu)
	if f := s.checkPackageIntegrity(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check critical binaries for suspicious characteristics
	if f := s.checkCriticalBinaries(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check dynamic linker integrity
	if f := s.checkDynamicLinker(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for library path hijacking
	if f := s.checkLibraryPaths(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for capability abuse on binaries
	if f := s.checkBinaryCapabilities(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("integrity scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *IntegrityScanner) checkPackageIntegrity(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Try dpkg -V first (Debian/Ubuntu)
	output, err := s.ExecCommand(ctx, "dpkg", "-V")
	if err == nil && output != "" {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// dpkg -V output format: status_flags path
			// Example: ??5?????? /usr/bin/somecommand (checksum changed)
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			status := parts[0]
			filePath := parts[1]

			// Parse status flags:
			// 5 = MD5 checksum mismatch
			// S = file size mismatch
			// c = config file
			// M = file type mismatch
			var severity entity.Severity

			if strings.Contains(status, "5") {
				// Checksum mismatch is serious
				severity = entity.SeverityHigh

				// Critical binaries are critical severity
				for _, critical := range criticalBinaries {
					if filePath == critical || strings.HasSuffix(critical, "/"+filepath.Base(filePath)) {
						severity = entity.SeverityCritical
						break
					}
				}

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("integrity-pkg-%s", filepath.Base(filePath)),
					Category:    "integrity",
					Severity:    severity,
					Title:       "Package file checksum mismatch",
					Description: fmt.Sprintf("File '%s' checksum doesn't match package database", filePath),
					Path:        filePath,
					Details: map[string]interface{}{
						"status_flags":   status,
						"verified_by":    "dpkg -V",
						"risk":           "File may have been modified or replaced",
						"interpretation": s.interpretDpkgStatus(status),
					},
				})
			}
		}
	}

	// Try rpm -Va for RHEL/CentOS
	output, err = s.ExecCommand(ctx, "rpm", "-Va")
	if err == nil && output != "" {
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			select {
			case <-ctx.Done():
				return findings
			default:
			}

			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Unsatisfied") {
				continue
			}

			// rpm -Va output format: SM5DLUGT  path
			parts := strings.Fields(line)
			if len(parts) < 2 {
				continue
			}

			status := parts[0]
			filePath := parts[len(parts)-1]

			if strings.Contains(status, "5") {
				severity := entity.SeverityHigh
				for _, critical := range criticalBinaries {
					if filePath == critical {
						severity = entity.SeverityCritical
						break
					}
				}

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("integrity-rpm-%s", filepath.Base(filePath)),
					Category:    "integrity",
					Severity:    severity,
					Title:       "RPM package file checksum mismatch",
					Description: fmt.Sprintf("File '%s' checksum doesn't match RPM database", filePath),
					Path:        filePath,
					Details: map[string]interface{}{
						"status_flags": status,
						"verified_by":  "rpm -Va",
					},
				})
			}
		}
	}

	return findings
}

func (s *IntegrityScanner) interpretDpkgStatus(status string) map[string]string {
	interpretation := make(map[string]string)

	flags := []struct {
		char   string
		meaning string
	}{
		{"5", "MD5 checksum changed"},
		{"S", "File size changed"},
		{"L", "Symlink changed"},
		{"T", "Modification time changed"},
		{"D", "Device number changed"},
		{"U", "User ownership changed"},
		{"G", "Group ownership changed"},
		{"M", "Mode (permissions) changed"},
	}

	for _, f := range flags {
		if strings.Contains(status, f.char) {
			interpretation[f.char] = f.meaning
		}
	}

	return interpretation
}

func (s *IntegrityScanner) checkCriticalBinaries(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	for _, binPath := range criticalBinaries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		info, err := os.Lstat(binPath)
		if err != nil {
			continue
		}

		// Check if it's a symlink (common for /bin -> /usr/bin)
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(binPath)
			if err == nil {
				s.log.Debug("binary is symlink", zap.String("path", binPath), zap.String("target", target))
			}
			continue
		}

		// Check for world-writable binaries
		if info.Mode()&0o002 != 0 {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("integrity-worldwrite-%s", filepath.Base(binPath)),
				Category:    "integrity",
				Severity:    entity.SeverityCritical,
				Title:       "World-writable system binary",
				Description: fmt.Sprintf("Critical binary '%s' is world-writable", binPath),
				Path:        binPath,
				Details: map[string]interface{}{
					"permissions": info.Mode().String(),
					"risk":        "Any user can modify this binary",
				},
			})
		}

		// Check for non-root ownership
		// Would need syscall for proper UID check, simplified here

		// Calculate and log hash for reference
		data, err := os.ReadFile(binPath)
		if err == nil {
			hash := fmt.Sprintf("%x", sha256.Sum256(data))
			s.log.Debug("binary hash",
				zap.String("path", binPath),
				zap.String("sha256", hash),
				zap.Int64("size", info.Size()),
			)
		}
	}

	return findings
}

func (s *IntegrityScanner) checkDynamicLinker(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	linkerPaths := []string{
		"/lib/ld-linux.so.2",
		"/lib64/ld-linux-x86-64.so.2",
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
	}

	for _, linkerPath := range linkerPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		info, err := os.Stat(linkerPath)
		if err != nil {
			continue
		}

		// Check permissions
		if info.Mode()&0o002 != 0 {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("integrity-linker-%s", filepath.Base(linkerPath)),
				Category:    "integrity",
				Severity:    entity.SeverityCritical,
				Title:       "World-writable dynamic linker",
				Description: fmt.Sprintf("Dynamic linker '%s' is world-writable", linkerPath),
				Path:        linkerPath,
				Details: map[string]interface{}{
					"permissions": info.Mode().String(),
					"risk":        "Complete system compromise possible via linker manipulation",
				},
			})
		}

		// Calculate hash
		data, err := os.ReadFile(linkerPath)
		if err == nil {
			hash := fmt.Sprintf("%x", sha256.Sum256(data))
			s.log.Debug("dynamic linker hash",
				zap.String("path", linkerPath),
				zap.String("sha256", hash),
			)
		}
	}

	// Check /etc/ld.so.conf and /etc/ld.so.conf.d/ for hijacking
	ldConfFiles := []string{"/etc/ld.so.conf"}

	// Add files from ld.so.conf.d
	confDir := "/etc/ld.so.conf.d"
	if entries, err := os.ReadDir(confDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
				ldConfFiles = append(ldConfFiles, filepath.Join(confDir, entry.Name()))
			}
		}
	}

	for _, confFile := range ldConfFiles {
		data, err := os.ReadFile(confFile)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// Check for suspicious library paths
			suspiciousPaths := []string{"/tmp", "/var/tmp", "/dev/shm", "/home"}
			for _, sus := range suspiciousPaths {
				if strings.HasPrefix(line, sus) {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("integrity-ldconf-%s-%d", filepath.Base(confFile), lineNum),
						Category:    "integrity",
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious library path in ld.so.conf",
						Description: fmt.Sprintf("Library path '%s' points to user-writable location", line),
						Path:        confFile,
						Details: map[string]interface{}{
							"line_number":    lineNum,
							"library_path":   line,
							"risk":           "Library path hijacking possible",
						},
					})
				}
			}
		}
	}

	return findings
}

func (s *IntegrityScanner) checkLibraryPaths(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check LD_LIBRARY_PATH in environment (should be empty for security)
	// Skip this check in WSL as LD_LIBRARY_PATH is commonly set for Windows interop
	ldLibPath := os.Getenv("LD_LIBRARY_PATH")
	if ldLibPath != "" {
		// Check if running in WSL
		isWSL := s.FileExists("/proc/sys/fs/binfmt_misc/WSLInterop")
		if isWSL {
			// In WSL, only flag if it points to suspicious locations
			if strings.Contains(ldLibPath, "/tmp") ||
				strings.Contains(ldLibPath, "/dev/shm") ||
				strings.Contains(ldLibPath, "/var/tmp") {
				findings = append(findings, &entity.Finding{
					ID:          "integrity-ld-library-path-suspicious",
					Category:    "integrity",
					Severity:    entity.SeverityHigh,
					Title:       "LD_LIBRARY_PATH points to temp directory",
					Description: "LD_LIBRARY_PATH contains suspicious temp directory path",
					Path:        "environment",
					Details: map[string]interface{}{
						"ld_library_path": ldLibPath,
						"risk":            "Library hijacking via temp directory",
					},
				})
			}
			// Otherwise skip in WSL - it's expected
		} else {
			findings = append(findings, &entity.Finding{
				ID:          "integrity-ld-library-path",
				Category:    "integrity",
				Severity:    entity.SeverityMedium,
				Title:       "LD_LIBRARY_PATH is set",
				Description: "LD_LIBRARY_PATH environment variable is set, which can be used for library hijacking",
				Path:        "environment",
				Details: map[string]interface{}{
					"ld_library_path": ldLibPath,
					"risk":            "Custom library paths can override system libraries",
				},
			})
		}
	}

	return findings
}

func (s *IntegrityScanner) checkBinaryCapabilities(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Use getcap to find binaries with capabilities
	output, err := s.ExecCommand(ctx, "getcap", "-r", "/usr", "/bin", "/sbin")
	if err != nil {
		// getcap might not be installed or might fail on some paths
		s.log.Debug("getcap command failed", zap.Error(err))
		return nil
	}

	// Suspicious capabilities that can be abused
	dangerousCaps := map[string]string{
		"cap_setuid":       "Can change UID, privilege escalation",
		"cap_setgid":       "Can change GID, privilege escalation",
		"cap_dac_override": "Bypasses file permission checks",
		"cap_dac_read_search": "Bypasses read permission checks",
		"cap_sys_admin":    "Various admin capabilities, very dangerous",
		"cap_sys_ptrace":   "Can trace processes, credential theft",
		"cap_net_raw":      "Raw network access, packet sniffing",
		"cap_net_admin":    "Network configuration, packet manipulation",
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Format: /path/to/binary cap_xxx+ep
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}

		binPath := parts[0]
		caps := strings.ToLower(parts[1])

		for cap, risk := range dangerousCaps {
			if strings.Contains(caps, cap) {
				// Check if this is a standard binary with expected caps
				// These are legitimate binaries that need capabilities for their function
				expectedCaps := map[string][]string{
					// Network tools
					"/usr/bin/ping":        {"cap_net_raw"},
					"/usr/bin/traceroute":  {"cap_net_raw"},
					"/usr/bin/mtr":         {"cap_net_raw"},
					"/usr/bin/mtr-packet":  {"cap_net_raw"},
					"/usr/sbin/traceroute": {"cap_net_raw"},

					// GStreamer PTP helper (Precision Time Protocol)
					"/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper": {"cap_net_admin", "cap_net_raw"},
					"/usr/libexec/gstreamer-1.0/gst-ptp-helper":                           {"cap_net_admin", "cap_net_raw"},

					// Wireshark dumpcap
					"/usr/bin/dumpcap": {"cap_net_admin", "cap_net_raw"},

					// Network time protocol
					"/usr/sbin/ntpd":    {"cap_sys_time", "cap_net_bind_service"},
					"/usr/sbin/chronyd": {"cap_sys_time", "cap_net_bind_service"},
				}

				isExpected := false
				if expected, ok := expectedCaps[binPath]; ok {
					for _, expCap := range expected {
						if strings.Contains(cap, expCap) {
							isExpected = true
							break
						}
					}
				}

				// Also allow if the binary basename matches common patterns
				baseName := filepath.Base(binPath)
				expectedBaseNames := map[string][]string{
					"ping":       {"cap_net_raw"},
					"ping4":      {"cap_net_raw"},
					"ping6":      {"cap_net_raw"},
					"mtr-packet": {"cap_net_raw"},
					"gst-ptp-helper": {"cap_net_admin", "cap_net_raw"},
				}
				if expected, ok := expectedBaseNames[baseName]; ok {
					for _, expCap := range expected {
						if strings.Contains(cap, expCap) {
							isExpected = true
							break
						}
					}
				}

				if !isExpected {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("integrity-cap-%s-%s", filepath.Base(binPath), cap),
						Category:    "integrity",
						Severity:    entity.SeverityHigh,
						Title:       "Binary with dangerous capability",
						Description: fmt.Sprintf("'%s' has %s capability", binPath, cap),
						Path:        binPath,
						Details: map[string]interface{}{
							"capabilities":  caps,
							"dangerous_cap": cap,
							"risk":          risk,
						},
					})
				}
			}
		}
	}

	return findings
}
