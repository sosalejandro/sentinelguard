package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type FilesystemScanner struct {
	BaseScanner
}

func NewFilesystemScanner() *FilesystemScanner {
	return &FilesystemScanner{
		BaseScanner: NewBaseScanner("filesystem", "Scans filesystem for suspicious files and permissions"),
	}
}

func (s *FilesystemScanner) Category() entity.FindingCategory {
	return entity.CategoryFileSystem
}

func (s *FilesystemScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting filesystem scan")

	var findings []*entity.Finding

	suidFindings := s.scanSUIDFiles(ctx)
	findings = append(findings, suidFindings...)

	hiddenFindings := s.scanHiddenFiles(ctx)
	findings = append(findings, hiddenFindings...)

	tempFindings := s.scanTempDirectories(ctx)
	findings = append(findings, tempFindings...)

	recentBinFindings := s.scanRecentlyModifiedBinaries(ctx)
	findings = append(findings, recentBinFindings...)

	s.Logger().Debug("filesystem scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *FilesystemScanner) scanSUIDFiles(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning SUID/SGID files")

	lines, err := s.RunCommand(ctx, "find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"-perm", "/4000", "-o", "-perm", "/2000", "-type", "f")
	if err != nil {
		return nil
	}

	var findings []*entity.Finding
	knownSUID := map[string]bool{
		// Core system utilities
		"/usr/bin/sudo": true, "/usr/bin/su": true, "/usr/bin/passwd": true,
		"/usr/bin/chsh": true, "/usr/bin/chfn": true, "/usr/bin/newgrp": true,
		"/usr/bin/gpasswd": true, "/usr/bin/mount": true, "/usr/bin/umount": true,
		"/usr/bin/pkexec": true, "/usr/bin/fusermount3": true, "/usr/bin/fusermount": true,
		"/bin/su": true, "/bin/mount": true, "/bin/umount": true,

		// Password/shadow utilities
		"/usr/bin/chage": true, "/usr/bin/expiry": true,
		"/usr/sbin/pam_extrausers_chkpwd": true, "/usr/sbin/unix_chkpwd": true,

		// SSH utilities
		"/usr/bin/ssh-agent": true,
		"/usr/lib/openssh/ssh-keysign": true,

		// Cron
		"/usr/bin/crontab": true,

		// DBus and polkit
		"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": true,
		"/usr/libexec/polkit-agent-helper-1":          true,
		"/usr/lib/polkit-1/polkit-agent-helper-1":     true,

		// Other common SGID binaries
		"/usr/bin/wall":       true,
		"/usr/bin/write":      true,
		"/usr/bin/bsd-write":  true,
		"/usr/bin/dotlockfile": true,
		"/usr/bin/at":         true,
		"/usr/bin/mlocate":    true,
		"/usr/bin/locate":     true,
	}

	for _, path := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		if strings.Contains(path, "/snap/") {
			continue
		}

		if !knownSUID[path] {
			finding := entity.NewFinding(
				entity.CategoryFileSystem,
				entity.SeverityMedium,
				"Unknown SUID/SGID binary",
				"SUID/SGID binary not in known safe list",
			).WithPath(path)

			info, err := os.Stat(path)
			if err == nil {
				finding.WithDetail("permissions", info.Mode().String())
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *FilesystemScanner) scanHiddenFiles(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning for suspicious hidden files")

	var findings []*entity.Finding
	suspiciousDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}

	for _, dir := range suspiciousDirs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, ".") {
				continue
			}

			if name == "." || name == ".." {
				continue
			}

			path := filepath.Join(dir, name)

			if strings.HasPrefix(name, "...") || name == ". " || name == ".. " {
				finding := entity.NewFinding(
					entity.CategoryFileSystem,
					entity.SeverityCritical,
					"Suspiciously named hidden file/directory",
					"File uses deceptive naming convention",
				).WithPath(path)
				findings = append(findings, finding)
				continue
			}

			info, err := entry.Info()
			if err != nil {
				continue
			}

			if info.Mode().IsRegular() && info.Mode()&0111 != 0 {
				finding := entity.NewFinding(
					entity.CategoryFileSystem,
					entity.SeverityHigh,
					"Executable hidden file in temp directory",
					"Hidden executable found in world-writable location",
				).WithPath(path).
					WithDetail("permissions", info.Mode().String()).
					WithDetail("size", info.Size())
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (s *FilesystemScanner) scanTempDirectories(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning temp directories for scripts")

	var findings []*entity.Finding
	tempDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}

	scriptExtensions := map[string]bool{
		".sh": true, ".py": true, ".pl": true, ".rb": true,
		".php": true, ".bash": true, ".zsh": true,
	}

	for _, dir := range tempDirs {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			name := entry.Name()
			ext := strings.ToLower(filepath.Ext(name))

			if scriptExtensions[ext] {
				path := filepath.Join(dir, name)
				finding := entity.NewFinding(
					entity.CategoryFileSystem,
					entity.SeverityMedium,
					"Script file in temp directory",
					"Script found in world-writable temp location",
				).WithPath(path).
					WithDetail("extension", ext)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (s *FilesystemScanner) scanRecentlyModifiedBinaries(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning for recently modified system binaries")

	lines, err := s.RunCommand(ctx, "find", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
		"-type", "f", "-mtime", "-7")
	if err != nil {
		return nil
	}

	var findings []*entity.Finding
	for _, path := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}

		// Check if file is package-managed (skip false positives from updates)
		if s.isPackageManaged(ctx, path) {
			continue
		}

		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		finding := entity.NewFinding(
			entity.CategoryFileSystem,
			entity.SeverityMedium,
			"Recently modified system binary",
			"System binary was modified within the last 7 days (not package-managed)",
		).WithPath(path).
			WithDetail("modified", info.ModTime().String()).
			WithDetail("size", strconv.FormatInt(info.Size(), 10))
		findings = append(findings, finding)
	}

	return findings
}

// isPackageManaged checks if a file is managed by dpkg or rpm
func (s *FilesystemScanner) isPackageManaged(ctx context.Context, path string) bool {
	// Try dpkg -S (Debian/Ubuntu)
	_, err := s.RunCommand(ctx, "dpkg", "-S", path)
	if err == nil {
		return true
	}

	// Try rpm -qf (RHEL/CentOS)
	_, err = s.RunCommand(ctx, "rpm", "-qf", path)
	return err == nil
}
