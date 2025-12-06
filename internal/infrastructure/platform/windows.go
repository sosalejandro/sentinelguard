package platform

import (
	"context"
	"errors"
)

// WindowsStrategy implements ScanStrategy for Windows systems
type WindowsStrategy struct {
	info *PlatformInfo
}

// NewWindowsStrategy creates a new Windows scanning strategy
func NewWindowsStrategy(info *PlatformInfo) *WindowsStrategy {
	return &WindowsStrategy{info: info}
}

func (s *WindowsStrategy) Name() string {
	return "windows"
}

func (s *WindowsStrategy) AvailableTools() []string {
	// Windows tools that could be used for scanning
	return []string{
		"powershell",
		"netstat",
		"tasklist",
		"wmic",
		"schtasks",
		"reg",
		"icacls",
	}
}

func (s *WindowsStrategy) SupportedScanners() []string {
	// Windows-specific scanners
	return []string{
		"network",
		"process",
		"filesystem",
		"user",
		"persistence", // Registry, scheduled tasks, services
		// Future: registry, services, wmi, startup
	}
}

func (s *WindowsStrategy) ExecuteCommand(ctx context.Context, name string, args ...string) (string, error) {
	// Windows command execution - would use PowerShell or cmd
	return "", errors.New("windows support not yet implemented")
}

func (s *WindowsStrategy) GetUserCrontab(ctx context.Context) ([]string, error) {
	// Windows uses Task Scheduler instead of cron
	// Would use: schtasks /query /fo LIST /v
	return nil, errors.New("use GetScheduledTasks for Windows")
}

func (s *WindowsStrategy) GetSystemServices(ctx context.Context) ([]ServiceInfo, error) {
	// Windows services via sc query or Get-Service
	return nil, errors.New("windows service query not yet implemented")
}

func (s *WindowsStrategy) GetNetworkConnections(ctx context.Context) ([]ConnectionInfo, error) {
	// Windows netstat or Get-NetTCPConnection
	return nil, errors.New("windows network query not yet implemented")
}

func (s *WindowsStrategy) GetProcessList(ctx context.Context) ([]ProcessInfo, error) {
	// Windows tasklist or Get-Process
	return nil, errors.New("windows process query not yet implemented")
}

// Windows-specific methods that could be added:

// GetScheduledTasks returns Windows scheduled tasks
func (s *WindowsStrategy) GetScheduledTasks(ctx context.Context) ([]ScheduledTask, error) {
	return nil, errors.New("not yet implemented")
}

// GetRegistryStartup returns startup entries from Windows registry
func (s *WindowsStrategy) GetRegistryStartup(ctx context.Context) ([]RegistryEntry, error) {
	return nil, errors.New("not yet implemented")
}

// GetWindowsServices returns Windows services with detailed info
func (s *WindowsStrategy) GetWindowsServices(ctx context.Context) ([]WindowsService, error) {
	return nil, errors.New("not yet implemented")
}

// ScheduledTask represents a Windows scheduled task
type ScheduledTask struct {
	Name        string
	Path        string
	State       string
	Triggers    []string
	Actions     []string
	NextRunTime string
	LastRunTime string
}

// RegistryEntry represents a Windows registry entry
type RegistryEntry struct {
	Key   string
	Name  string
	Type  string
	Value string
}

// WindowsService represents a Windows service
type WindowsService struct {
	Name        string
	DisplayName string
	State       string
	StartType   string
	BinaryPath  string
	Account     string
}
