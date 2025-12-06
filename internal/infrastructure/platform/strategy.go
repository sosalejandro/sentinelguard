package platform

import (
	"context"
)

// ScanStrategy defines platform-specific scanning behavior
type ScanStrategy interface {
	// Name returns the strategy name
	Name() string

	// AvailableTools returns tools available on this platform
	AvailableTools() []string

	// SupportedScanners returns scanner names supported on this platform
	SupportedScanners() []string

	// ExecuteCommand executes a command with platform-specific handling
	ExecuteCommand(ctx context.Context, name string, args ...string) (string, error)

	// GetUserCrontab returns the user's crontab content
	GetUserCrontab(ctx context.Context) ([]string, error)

	// GetSystemServices returns system services
	GetSystemServices(ctx context.Context) ([]ServiceInfo, error)

	// GetNetworkConnections returns active network connections
	GetNetworkConnections(ctx context.Context) ([]ConnectionInfo, error)

	// GetProcessList returns running processes
	GetProcessList(ctx context.Context) ([]ProcessInfo, error)
}

// ServiceInfo represents a system service
type ServiceInfo struct {
	Name    string
	Status  string
	Enabled bool
	Type    string // systemd, sysvinit, launchd, windows-service
}

// ConnectionInfo represents a network connection
type ConnectionInfo struct {
	Protocol    string
	LocalAddr   string
	LocalPort   int
	RemoteAddr  string
	RemotePort  int
	State       string
	PID         int
	ProcessName string
}

// ProcessInfo represents a running process
type ProcessInfo struct {
	PID        int
	PPID       int
	Name       string
	User       string
	Command    string
	Executable string
}

// StrategyFactory creates the appropriate strategy for the detected platform
func StrategyFactory(info *PlatformInfo) ScanStrategy {
	switch info.OS {
	case OSLinux:
		return NewLinuxStrategy(info)
	case OSWindows:
		return NewWindowsStrategy(info)
	case OSDarwin:
		return NewDarwinStrategy(info)
	default:
		return NewLinuxStrategy(info) // Default to Linux
	}
}
