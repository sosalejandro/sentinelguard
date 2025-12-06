package platform

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// LinuxStrategy implements ScanStrategy for Linux systems
type LinuxStrategy struct {
	info *PlatformInfo
}

// NewLinuxStrategy creates a new Linux scanning strategy
func NewLinuxStrategy(info *PlatformInfo) *LinuxStrategy {
	return &LinuxStrategy{info: info}
}

func (s *LinuxStrategy) Name() string {
	return "linux"
}

func (s *LinuxStrategy) AvailableTools() []string {
	tools := []string{}

	toolList := []string{
		"ss", "netstat", "lsof", "ps", "pgrep",
		"getcap", "lsmod", "systemctl", "journalctl",
		"dpkg", "rpm", "apt", "yum",
		"find", "grep", "awk", "sed",
	}

	for _, tool := range toolList {
		if commandExists(tool) {
			tools = append(tools, tool)
		}
	}

	return tools
}

func (s *LinuxStrategy) SupportedScanners() []string {
	scanners := []string{
		"network",
		"process",
		"filesystem",
		"user",
		"ssh",
		"persistence",
	}

	// Add Linux-specific scanners
	if s.info.OS == OSLinux {
		scanners = append(scanners,
			"cron",
			"kernel",
			"pam",
			"memory",
			"integrity",
			"boot",
		)
	}

	return scanners
}

func (s *LinuxStrategy) ExecuteCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *LinuxStrategy) GetUserCrontab(ctx context.Context) ([]string, error) {
	output, err := s.ExecuteCommand(ctx, "crontab", "-l")
	if err != nil {
		return nil, err
	}
	return strings.Split(output, "\n"), nil
}

func (s *LinuxStrategy) GetSystemServices(ctx context.Context) ([]ServiceInfo, error) {
	var services []ServiceInfo

	if s.info.HasSystemd {
		// Use systemctl for systemd systems
		output, err := s.ExecuteCommand(ctx, "systemctl", "list-unit-files", "--type=service", "--no-pager", "--plain")
		if err != nil {
			return nil, err
		}

		lines := strings.Split(output, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.HasSuffix(fields[0], ".service") {
				services = append(services, ServiceInfo{
					Name:    strings.TrimSuffix(fields[0], ".service"),
					Status:  fields[1],
					Enabled: fields[1] == "enabled",
					Type:    "systemd",
				})
			}
		}
	} else {
		// Fall back to sysvinit style
		entries, err := os.ReadDir("/etc/init.d")
		if err != nil {
			return nil, err
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				services = append(services, ServiceInfo{
					Name: entry.Name(),
					Type: "sysvinit",
				})
			}
		}
	}

	return services, nil
}

func (s *LinuxStrategy) GetNetworkConnections(ctx context.Context) ([]ConnectionInfo, error) {
	var connections []ConnectionInfo

	// Prefer ss over netstat
	if commandExists("ss") {
		output, err := s.ExecuteCommand(ctx, "ss", "-tlnp")
		if err == nil {
			connections = append(connections, parseSSOutput(output)...)
		}
	} else if commandExists("netstat") {
		output, err := s.ExecuteCommand(ctx, "netstat", "-tlnp")
		if err == nil {
			connections = append(connections, parseNetstatOutput(output)...)
		}
	}

	return connections, nil
}

func (s *LinuxStrategy) GetProcessList(ctx context.Context) ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// Read from /proc directly for accuracy
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID directory
		}

		procInfo := ProcessInfo{PID: pid}

		// Read comm (process name)
		if data, err := os.ReadFile("/proc/" + entry.Name() + "/comm"); err == nil {
			procInfo.Name = strings.TrimSpace(string(data))
		}

		// Read cmdline
		if data, err := os.ReadFile("/proc/" + entry.Name() + "/cmdline"); err == nil {
			procInfo.Command = strings.ReplaceAll(string(data), "\x00", " ")
		}

		// Read exe symlink
		if link, err := os.Readlink("/proc/" + entry.Name() + "/exe"); err == nil {
			procInfo.Executable = link
		}

		// Read status for PPID and user
		if data, err := os.ReadFile("/proc/" + entry.Name() + "/status"); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "PPid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						procInfo.PPID, _ = strconv.Atoi(fields[1])
					}
				}
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(line)
					if len(fields) >= 2 {
						uid, _ := strconv.Atoi(fields[1])
						procInfo.User = lookupUser(uid)
					}
				}
			}
		}

		processes = append(processes, procInfo)
	}

	return processes, nil
}

func parseSSOutput(output string) []ConnectionInfo {
	var connections []ConnectionInfo
	lines := strings.Split(output, "\n")

	for _, line := range lines[1:] { // Skip header
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Parse local address:port
		localParts := strings.Split(fields[3], ":")
		if len(localParts) < 2 {
			continue
		}

		port, _ := strconv.Atoi(localParts[len(localParts)-1])
		addr := strings.Join(localParts[:len(localParts)-1], ":")

		conn := ConnectionInfo{
			Protocol:  "tcp",
			LocalAddr: addr,
			LocalPort: port,
			State:     fields[0],
		}

		// Parse process info if available
		if len(fields) >= 6 {
			// Format: users:(("process",pid=123,fd=4))
			procInfo := fields[5]
			if strings.Contains(procInfo, "pid=") {
				start := strings.Index(procInfo, "pid=")
				if start != -1 {
					end := strings.IndexAny(procInfo[start:], ",)")
					if end != -1 {
						pidStr := procInfo[start+4 : start+end]
						conn.PID, _ = strconv.Atoi(pidStr)
					}
				}
			}
		}

		connections = append(connections, conn)
	}

	return connections
}

func parseNetstatOutput(output string) []ConnectionInfo {
	var connections []ConnectionInfo
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if !strings.HasPrefix(line, "tcp") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// Parse local address:port
		localParts := strings.Split(fields[3], ":")
		if len(localParts) < 2 {
			continue
		}

		port, _ := strconv.Atoi(localParts[len(localParts)-1])
		addr := strings.Join(localParts[:len(localParts)-1], ":")

		conn := ConnectionInfo{
			Protocol:  "tcp",
			LocalAddr: addr,
			LocalPort: port,
			State:     fields[5],
		}

		// Parse PID/Program
		if len(fields) >= 7 {
			pidProg := fields[6]
			if strings.Contains(pidProg, "/") {
				parts := strings.SplitN(pidProg, "/", 2)
				conn.PID, _ = strconv.Atoi(parts[0])
				if len(parts) > 1 {
					conn.ProcessName = parts[1]
				}
			}
		}

		connections = append(connections, conn)
	}

	return connections
}

func lookupUser(uid int) string {
	// Simple user lookup from /etc/passwd
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return strconv.Itoa(uid)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) >= 3 {
			userUID, _ := strconv.Atoi(fields[2])
			if userUID == uid {
				return fields[0]
			}
		}
	}

	return strconv.Itoa(uid)
}
