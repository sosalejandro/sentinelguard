package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// MemoryScanner detects hidden processes, process injection, and memory anomalies
type MemoryScanner struct {
	BaseScanner
}

// Suspicious patterns in memory maps
var (
	// Shellcode signatures (common byte patterns)
	shellcodePatterns = []string{
		"\\x31\\xc0",      // xor eax, eax (common shellcode start)
		"\\x48\\x31\\xc0", // xor rax, rax (64-bit)
		"/bin/sh",
		"/bin/bash",
		"socket",
		"connect",
		"execve",
	}

	// Suspicious library patterns - be very specific to reduce false positives
	suspiciousLibPatterns = []string{
		"libpreload",
		"librouter",
		"librootkit",
		"libkeylog",
		"libpayload",
	}
)

func NewMemoryScanner() *MemoryScanner {
	return &MemoryScanner{
		BaseScanner: NewBaseScanner("memory", "Hidden process and memory injection detector"),
	}
}

func (s *MemoryScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting memory and hidden process scan")
	var findings []*entity.Finding

	// Detect hidden processes (compare ps output with /proc)
	if f := s.detectHiddenProcesses(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for processes with deleted executables
	if f := s.checkDeletedExecutables(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for suspicious memory mappings
	if f := s.checkMemoryMappings(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for process name spoofing
	if f := s.detectNameSpoofing(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for injected libraries
	if f := s.checkInjectedLibraries(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for ptrace attachments (debugger/injector)
	if f := s.checkPtraceStatus(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("memory scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *MemoryScanner) detectHiddenProcesses(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Get list of PIDs from /proc
	procPids := make(map[int]bool)
	entries, err := os.ReadDir("/proc")
	if err != nil {
		s.log.Debug("cannot read /proc", zap.Error(err))
		return nil
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if pid, err := strconv.Atoi(entry.Name()); err == nil {
			procPids[pid] = true
		}
	}

	// Get list of PIDs from ps
	output, err := s.ExecCommand(ctx, "ps", "-eo", "pid", "--no-headers")
	if err != nil {
		s.log.Debug("cannot run ps", zap.Error(err))
		return nil
	}

	psPids := make(map[int]bool)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if pid, err := strconv.Atoi(line); err == nil {
			psPids[pid] = true
		}
	}

	// Check for PIDs in /proc but not in ps (potentially hidden from ps)
	for pid := range procPids {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !psPids[pid] {
			// Verify it's a real process
			statusPath := filepath.Join("/proc", strconv.Itoa(pid), "status")
			if _, err := os.Stat(statusPath); err == nil {
				// Read process name
				comm := s.readProcFile(pid, "comm")
				cmdline := s.readProcFile(pid, "cmdline")

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("memory-hidden-pid-%d", pid),
					Category:    "memory",
					Severity:    entity.SeverityCritical,
					Title:       "Potentially hidden process detected",
					Description: fmt.Sprintf("PID %d exists in /proc but not visible in ps output", pid),
					Path:        fmt.Sprintf("/proc/%d", pid),
					Details: map[string]interface{}{
						"pid":      pid,
						"comm":     comm,
						"cmdline":  cmdline,
						"in_proc":  true,
						"in_ps":    false,
						"technique": "Process hiding from userspace tools",
					},
				})
			}
		}
	}

	// Check for PIDs in ps but not in /proc (rare, indicates kernel manipulation)
	// Note: Race conditions can cause false positives when processes exit during scan
	// We use multiple verification passes to reduce false positives
	for pid := range psPids {
		if !procPids[pid] {
			// First check: verify /proc entry is actually missing
			procPath := fmt.Sprintf("/proc/%d", pid)
			if _, err := os.Stat(procPath); err == nil {
				// Process exists now - race condition, skip
				continue
			}

			// Second check: wait briefly and verify again (process exit race)
			// Most short-lived processes will have completed by now
			time.Sleep(10 * time.Millisecond)
			if _, err := os.Stat(procPath); err == nil {
				// Process appeared - race condition
				continue
			}

			// Third check: try to read /proc/[pid]/stat to confirm truly missing
			statPath := filepath.Join(procPath, "stat")
			if _, err := os.ReadFile(statPath); err == nil {
				// Can read stat - process exists
				continue
			}

			// Process is genuinely missing from /proc but was in ps
			// This is rare and could indicate kernel-level hiding
			// Log at debug level - most cases are legitimate process exits
			s.log.Debug("PID in ps but consistently missing from /proc",
				zap.Int("pid", pid),
				zap.String("note", "Could be process exit during scan or kernel manipulation"))
		}
	}

	return findings
}

func (s *MemoryScanner) checkDeletedExecutables(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		exePath := filepath.Join("/proc", entry.Name(), "exe")
		link, err := os.Readlink(exePath)
		if err != nil {
			continue
		}

		// Check for deleted executable
		if strings.HasSuffix(link, " (deleted)") {
			comm := s.readProcFile(pid, "comm")
			cmdline := s.readProcFile(pid, "cmdline")

			// Get original path
			originalPath := strings.TrimSuffix(link, " (deleted)")

			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("memory-deleted-exe-%d", pid),
				Category:    "memory",
				Severity:    entity.SeverityHigh,
				Title:       "Process running from deleted executable",
				Description: fmt.Sprintf("PID %d executable has been deleted from disk", pid),
				Path:        exePath,
				Details: map[string]interface{}{
					"pid":           pid,
					"comm":          comm,
					"cmdline":       cmdline,
					"original_path": originalPath,
					"risk":          "May indicate in-memory malware or cleanup evasion",
				},
			})
		}
	}

	return findings
}

func (s *MemoryScanner) checkMemoryMappings(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		mapsPath := filepath.Join("/proc", entry.Name(), "maps")
		file, err := os.Open(mapsPath)
		if err != nil {
			continue
		}

		comm := s.readProcFile(pid, "comm")

		scanner := bufio.NewScanner(file)
		anonExecCount := 0

		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			perms := fields[1]
			pathField := ""
			if len(fields) >= 6 {
				pathField = fields[5]
			}

			// Check for anonymous executable memory (rwxp with no file backing)
			// This can indicate shellcode injection
			if strings.Contains(perms, "x") && strings.Contains(perms, "w") {
				if pathField == "" || pathField == "[stack]" || pathField == "[heap]" {
					anonExecCount++
				}
			}

			// Check for suspicious mapped libraries
			for _, pattern := range suspiciousLibPatterns {
				if strings.Contains(strings.ToLower(pathField), pattern) {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("memory-suslib-%d-%s", pid, pattern),
						Category:    "memory",
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious library mapped in process",
						Description: fmt.Sprintf("PID %d (%s) has suspicious library: %s", pid, comm, pathField),
						Path:        mapsPath,
						Details: map[string]interface{}{
							"pid":     pid,
							"comm":    comm,
							"library": pathField,
							"pattern": pattern,
							"mapping": line,
						},
					})
				}
			}
		}
		file.Close()

		// Multiple anonymous executable regions is suspicious
		// However, JIT runtimes (Node.js, Java, Python, etc.) legitimately use many
		jitRuntimes := []string{"node", "java", "python", "ruby", "php", "dotnet", "mono", "julia", "luajit", "claude"}
		isJITRuntime := false
		commLower := strings.ToLower(comm)
		for _, runtime := range jitRuntimes {
			if strings.Contains(commLower, runtime) {
				isJITRuntime = true
				break
			}
		}

		// Only report if not a known JIT runtime AND count is very high
		if anonExecCount > 10 && !isJITRuntime {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("memory-anonexec-%d", pid),
				Category:    "memory",
				Severity:    entity.SeverityMedium,
				Title:       "Multiple anonymous executable memory regions",
				Description: fmt.Sprintf("PID %d (%s) has %d anonymous executable regions", pid, comm, anonExecCount),
				Path:        mapsPath,
				Details: map[string]interface{}{
					"pid":                    pid,
					"comm":                   comm,
					"anonymous_exec_regions": anonExecCount,
					"risk":                   "May indicate code injection",
				},
			})
		}
	}

	return findings
}

func (s *MemoryScanner) detectNameSpoofing(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		// Get the actual binary name from exe symlink
		exePath := filepath.Join("/proc", entry.Name(), "exe")
		exeLink, err := os.Readlink(exePath)
		if err != nil {
			continue
		}

		exeName := filepath.Base(strings.TrimSuffix(exeLink, " (deleted)"))

		// Get the reported process name from comm
		comm := strings.TrimSpace(s.readProcFile(pid, "comm"))

		// Compare - significant mismatch might indicate spoofing
		// Note: comm is limited to 15 chars, so truncate exeName for comparison
		truncExeName := exeName
		if len(truncExeName) > 15 {
			truncExeName = truncExeName[:15]
		}

		// Check for complete mismatch (not just truncation)
		if comm != "" && truncExeName != "" && !strings.HasPrefix(truncExeName, comm) && !strings.HasPrefix(comm, truncExeName) {
			// Allow common legitimate mismatches
			knownMismatches := map[string][]string{
				"bash":   {"sh", "-bash"},
				"python": {"python3", "python2"},
				"node":   {"nodejs", "npm"},
			}

			// Also allow npm patterns and known node-based tools
			// Node processes often show "npm exec ...", "npm run ...", or tool names like "claude"
			cmdline := s.readProcFile(pid, "cmdline")
			if exeName == "node" {
				// Known legitimate node-based tools
				nodeTools := []string{"npm", "npx", "claude", "yarn", "pnpm", "tsx", "ts-node"}
				isNodeTool := false
				for _, tool := range nodeTools {
					if strings.Contains(cmdline, tool) || strings.Contains(comm, tool) {
						isNodeTool = true
						break
					}
				}
				if isNodeTool {
					continue // Skip to next PID
				}
			}

			legitimate := false
			for base, alts := range knownMismatches {
				if strings.Contains(exeName, base) {
					for _, alt := range alts {
						if strings.Contains(comm, alt) || strings.Contains(alt, comm) {
							legitimate = true
							break
						}
					}
				}
			}

			if !legitimate && !strings.Contains(exeName, comm) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("memory-namespoofing-%d", pid),
					Category:    "memory",
					Severity:    entity.SeverityMedium,
					Title:       "Possible process name spoofing",
					Description: fmt.Sprintf("PID %d binary name '%s' doesn't match reported name '%s'", pid, exeName, comm),
					Path:        exePath,
					Details: map[string]interface{}{
						"pid":         pid,
						"binary_name": exeName,
						"comm_name":   comm,
						"risk":        "Process may be disguising itself",
					},
				})
			}
		}
	}

	return findings
}

func (s *MemoryScanner) checkInjectedLibraries(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check LD_PRELOAD environment for all processes
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		environPath := filepath.Join("/proc", entry.Name(), "environ")
		data, err := os.ReadFile(environPath)
		if err != nil {
			continue
		}

		// Parse environment variables (null-separated)
		envVars := strings.Split(string(data), "\x00")
		for _, env := range envVars {
			if strings.HasPrefix(env, "LD_PRELOAD=") {
				preloadValue := strings.TrimPrefix(env, "LD_PRELOAD=")
				if preloadValue != "" {
					comm := s.readProcFile(pid, "comm")

					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("memory-ldpreload-%d", pid),
						Category:    "memory",
						Severity:    entity.SeverityHigh,
						Title:       "Process running with LD_PRELOAD",
						Description: fmt.Sprintf("PID %d (%s) has LD_PRELOAD set", pid, comm),
						Path:        environPath,
						Details: map[string]interface{}{
							"pid":        pid,
							"comm":       comm,
							"ld_preload": preloadValue,
							"risk":       "Library injection active for this process",
						},
					})
				}
			}
		}
	}

	// Check /etc/ld.so.preload (system-wide preload)
	ldPreloadPath := "/etc/ld.so.preload"
	if data, err := os.ReadFile(ldPreloadPath); err == nil && len(data) > 0 {
		content := strings.TrimSpace(string(data))
		if content != "" {
			findings = append(findings, &entity.Finding{
				ID:          "memory-system-ldpreload",
				Category:    "memory",
				Severity:    entity.SeverityCritical,
				Title:       "System-wide library preload configured",
				Description: "/etc/ld.so.preload contains library preload entries",
				Path:        ldPreloadPath,
				Details: map[string]interface{}{
					"content": content,
					"risk":    "All dynamically-linked programs will load these libraries",
				},
			})
		}
	}

	return findings
}

func (s *MemoryScanner) checkPtraceStatus(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	// Pattern to extract TracerPid from status
	tracerPidRegex := regexp.MustCompile(`TracerPid:\s*(\d+)`)

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		statusPath := filepath.Join("/proc", entry.Name(), "status")
		data, err := os.ReadFile(statusPath)
		if err != nil {
			continue
		}

		matches := tracerPidRegex.FindStringSubmatch(string(data))
		if len(matches) >= 2 {
			tracerPid, _ := strconv.Atoi(matches[1])
			if tracerPid > 0 {
				comm := s.readProcFile(pid, "comm")
				tracerComm := s.readProcFile(tracerPid, "comm")

				// Ignore common legitimate debuggers
				legitimateDebuggers := []string{"gdb", "strace", "ltrace", "lldb", "valgrind"}
				isLegitimate := false
				for _, debugger := range legitimateDebuggers {
					if strings.Contains(tracerComm, debugger) {
						isLegitimate = true
						break
					}
				}

				if !isLegitimate {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("memory-ptrace-%d", pid),
						Category:    "memory",
						Severity:    entity.SeverityMedium,
						Title:       "Process being traced by unknown tracer",
						Description: fmt.Sprintf("PID %d (%s) is being traced by PID %d (%s)", pid, comm, tracerPid, tracerComm),
						Path:        statusPath,
						Details: map[string]interface{}{
							"traced_pid":   pid,
							"traced_comm":  comm,
							"tracer_pid":   tracerPid,
							"tracer_comm":  tracerComm,
							"risk":         "May indicate process injection or credential theft",
						},
					})
				}
			}
		}
	}

	return findings
}

func (s *MemoryScanner) readProcFile(pid int, filename string) string {
	path := filepath.Join("/proc", strconv.Itoa(pid), filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	// Replace null bytes (used in cmdline)
	return strings.ReplaceAll(strings.TrimSpace(string(data)), "\x00", " ")
}
