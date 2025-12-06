package platform

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// DarwinStrategy implements ScanStrategy for macOS systems
type DarwinStrategy struct {
	info *PlatformInfo
}

// NewDarwinStrategy creates a new macOS scanning strategy
func NewDarwinStrategy(info *PlatformInfo) *DarwinStrategy {
	return &DarwinStrategy{info: info}
}

func (s *DarwinStrategy) Name() string {
	return "darwin"
}

func (s *DarwinStrategy) AvailableTools() []string {
	tools := []string{}

	toolList := []string{
		"lsof", "netstat", "ps", "pgrep",
		"launchctl", "dscl", "security",
		"kextstat", "spctl", "csrutil",
		"find", "grep", "awk", "sed",
	}

	for _, tool := range toolList {
		if commandExists(tool) {
			tools = append(tools, tool)
		}
	}

	return tools
}

func (s *DarwinStrategy) SupportedScanners() []string {
	return []string{
		"network",
		"process",
		"filesystem",
		"user",
		"ssh",
		"persistence",
		// Future: launchd, kext, gatekeeper
	}
}

func (s *DarwinStrategy) ExecuteCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *DarwinStrategy) GetUserCrontab(ctx context.Context) ([]string, error) {
	output, err := s.ExecuteCommand(ctx, "crontab", "-l")
	if err != nil {
		return nil, err
	}
	return strings.Split(output, "\n"), nil
}

func (s *DarwinStrategy) GetSystemServices(ctx context.Context) ([]ServiceInfo, error) {
	var services []ServiceInfo

	// Use launchctl for macOS services
	output, err := s.ExecuteCommand(ctx, "launchctl", "list")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines[1:] { // Skip header
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			services = append(services, ServiceInfo{
				Name:   fields[2],
				Status: fields[1], // Exit code or "-"
				Type:   "launchd",
			})
		}
	}

	return services, nil
}

func (s *DarwinStrategy) GetNetworkConnections(ctx context.Context) ([]ConnectionInfo, error) {
	var connections []ConnectionInfo

	// Use lsof for macOS network connections
	output, err := s.ExecuteCommand(ctx, "lsof", "-i", "-P", "-n")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines[1:] { // Skip header
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		// Parse command, PID, and network info
		pid, _ := strconv.Atoi(fields[1])

		conn := ConnectionInfo{
			ProcessName: fields[0],
			PID:         pid,
		}

		// Parse name field for address:port
		nameField := fields[len(fields)-1]
		if strings.Contains(nameField, "->") {
			// Connected socket
			parts := strings.Split(nameField, "->")
			if len(parts) >= 1 {
				localParts := strings.Split(parts[0], ":")
				if len(localParts) >= 2 {
					conn.LocalAddr = strings.Join(localParts[:len(localParts)-1], ":")
					conn.LocalPort, _ = strconv.Atoi(localParts[len(localParts)-1])
				}
			}
		} else if strings.Contains(nameField, ":") {
			// Listening socket
			localParts := strings.Split(nameField, ":")
			if len(localParts) >= 2 {
				conn.LocalAddr = strings.Join(localParts[:len(localParts)-1], ":")
				conn.LocalPort, _ = strconv.Atoi(localParts[len(localParts)-1])
			}
		}

		// Determine state from lsof output
		if strings.Contains(line, "(LISTEN)") {
			conn.State = "LISTEN"
		} else if strings.Contains(line, "(ESTABLISHED)") {
			conn.State = "ESTABLISHED"
		}

		connections = append(connections, conn)
	}

	return connections, nil
}

func (s *DarwinStrategy) GetProcessList(ctx context.Context) ([]ProcessInfo, error) {
	var processes []ProcessInfo

	output, err := s.ExecuteCommand(ctx, "ps", "-axo", "pid,ppid,user,comm,command")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines[1:] { // Skip header
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])

		proc := ProcessInfo{
			PID:        pid,
			PPID:       ppid,
			User:       fields[2],
			Name:       fields[3],
			Executable: fields[3],
		}

		if len(fields) > 4 {
			proc.Command = strings.Join(fields[4:], " ")
		}

		processes = append(processes, proc)
	}

	return processes, nil
}

// macOS-specific methods that could be added:

// GetLaunchAgents returns user and system LaunchAgents
func (s *DarwinStrategy) GetLaunchAgents(ctx context.Context) ([]LaunchAgent, error) {
	return nil, errors.New("not yet implemented")
}

// GetKernelExtensions returns loaded kernel extensions
func (s *DarwinStrategy) GetKernelExtensions(ctx context.Context) ([]KernelExtension, error) {
	return nil, errors.New("not yet implemented")
}

// GetGatekeeperStatus returns Gatekeeper and SIP status
func (s *DarwinStrategy) GetGatekeeperStatus(ctx context.Context) (*SecurityStatus, error) {
	return nil, errors.New("not yet implemented")
}

// LaunchAgent represents a macOS LaunchAgent/LaunchDaemon
type LaunchAgent struct {
	Label       string
	Path        string
	Program     string
	Arguments   []string
	RunAtLoad   bool
	KeepAlive   bool
	UserScope   bool // true for LaunchAgent, false for LaunchDaemon
}

// KernelExtension represents a loaded kext
type KernelExtension struct {
	Name       string
	Version    string
	Size       int64
	Linked     bool
	BundleID   string
	LoadAddr   string
}

// SecurityStatus represents macOS security features
type SecurityStatus struct {
	GatekeeperEnabled bool
	SIPEnabled        bool
	FileVaultEnabled  bool
}
