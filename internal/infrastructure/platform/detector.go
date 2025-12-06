package platform

import (
	"os"
	"runtime"
	"strings"
)

// OSType represents the detected operating system
type OSType string

const (
	OSLinux   OSType = "linux"
	OSWindows OSType = "windows"
	OSDarwin  OSType = "darwin"
	OSUnknown OSType = "unknown"
)

// Environment represents the execution environment
type Environment string

const (
	EnvNative    Environment = "native"
	EnvWSL       Environment = "wsl"
	EnvDocker    Environment = "docker"
	EnvContainer Environment = "container"
)

// PlatformInfo contains detailed platform detection results
type PlatformInfo struct {
	OS          OSType
	Environment Environment
	Arch        string
	IsRoot      bool
	HasSystemd  bool
	HasDocker   bool
	HasPodman   bool
	Distro      string
	Version     string
}

// Detect performs platform detection
func Detect() *PlatformInfo {
	info := &PlatformInfo{
		OS:   detectOS(),
		Arch: runtime.GOARCH,
	}

	info.Environment = detectEnvironment()
	info.IsRoot = os.Geteuid() == 0
	info.HasSystemd = fileExists("/run/systemd/system")
	info.HasDocker = fileExists("/var/run/docker.sock")
	info.HasPodman = commandExists("podman")
	info.Distro, info.Version = detectDistro()

	return info
}

func detectOS() OSType {
	switch runtime.GOOS {
	case "linux":
		return OSLinux
	case "windows":
		return OSWindows
	case "darwin":
		return OSDarwin
	default:
		return OSUnknown
	}
}

func detectEnvironment() Environment {
	// Check for WSL
	if fileExists("/proc/sys/fs/binfmt_misc/WSLInterop") {
		return EnvWSL
	}

	// Check kernel version for WSL
	if data, err := os.ReadFile("/proc/version"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "microsoft") {
			return EnvWSL
		}
	}

	// Check for Docker
	if fileExists("/.dockerenv") {
		return EnvDocker
	}

	// Check for generic container
	if isContainerized() {
		return EnvContainer
	}

	return EnvNative
}

func detectDistro() (distro, version string) {
	// Try /etc/os-release first (standard location)
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "ID=") {
				distro = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
			}
			if strings.HasPrefix(line, "VERSION_ID=") {
				version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
			}
		}
	}

	return distro, version
}

func isContainerized() bool {
	// Check cgroup for container indicators
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "lxc") ||
			strings.Contains(content, "kubepods") {
			return true
		}
	}

	// Check for systemd-detect-virt
	if data, err := os.ReadFile("/proc/1/environ"); err == nil {
		if strings.Contains(string(data), "container=") {
			return true
		}
	}

	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func commandExists(cmd string) bool {
	paths := []string{"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/"}
	for _, p := range paths {
		if fileExists(p + cmd) {
			return true
		}
	}
	return false
}

// String returns a human-readable description
func (p *PlatformInfo) String() string {
	return strings.Join([]string{
		string(p.OS),
		string(p.Environment),
		p.Arch,
		p.Distro,
		p.Version,
	}, "-")
}

// SupportsScanner checks if a scanner is supported on this platform
func (p *PlatformInfo) SupportsScanner(scannerName string) bool {
	// Define scanner support per platform
	linuxOnlyScanners := map[string]bool{
		"kernel":     true,
		"pam":        true,
		"boot":       true,
		"cron":       true,
		"systemd":    true,
		"memory":     true,
		"integrity":  true,
	}

	if p.OS != OSLinux && linuxOnlyScanners[scannerName] {
		return false
	}

	return true
}
