package scanner

import (
	"context"
	"os"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// ContainerScanner detects container escape vulnerabilities and suspicious container configurations
type ContainerScanner struct {
	BaseScanner
}

// Dangerous capabilities that could allow container escape
var dangerousCapabilities = map[string]string{
	"CAP_SYS_ADMIN":    "Full system administration - allows nearly any escape technique",
	"CAP_SYS_PTRACE":   "Process tracing - can attach to host processes",
	"CAP_SYS_MODULE":   "Kernel module loading - can load malicious modules",
	"CAP_DAC_READ_SEARCH": "Bypass file read permission - can read any file",
	"CAP_NET_ADMIN":    "Network administration - can manipulate network stack",
	"CAP_NET_RAW":      "Raw socket access - can sniff network traffic",
	"CAP_SYS_RAWIO":    "Raw I/O access - can directly access hardware",
	"CAP_SYS_CHROOT":   "Chroot capability - can escape chroot environments",
	"CAP_SETUID":       "Set UID - can escalate privileges",
	"CAP_SETGID":       "Set GID - can escalate privileges",
	"CAP_MKNOD":        "Create device files - can create device nodes",
	"CAP_DAC_OVERRIDE": "Bypass file permissions - can write to any file",
}

// Known container escape paths (reserved for enhanced escape detection)
var _ = []string{
	"/var/run/docker.sock",       // Docker socket mount
	"/run/docker.sock",           // Alternative Docker socket location
	"/var/run/containerd/containerd.sock", // Containerd socket
	"/proc/sys/kernel",           // Kernel parameters (writable = escape)
	"/sys/fs/cgroup",             // Cgroup access
	"/dev/mem",                   // Physical memory access
	"/dev/kmem",                  // Kernel memory access
}

func NewContainerScanner() *ContainerScanner {
	return &ContainerScanner{
		BaseScanner: NewBaseScanner("container", "Detects container escape vulnerabilities and security misconfigurations"),
	}
}

func (s *ContainerScanner) Category() entity.FindingCategory {
	return entity.CategoryPersistence
}

func (s *ContainerScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting container security scan")

	var findings []*entity.Finding

	// Only run if we're inside a container
	if !s.isInsideContainer() {
		s.Logger().Debug("not running inside a container, checking for container runtime")
		// Still check for exposed Docker sockets on the host
		socketFindings := s.checkExposedDockerSockets(ctx)
		findings = append(findings, socketFindings...)
		return findings, nil
	}

	s.Logger().Debug("running inside container, checking for escape vectors")

	// Check for privileged container
	if f := s.checkPrivilegedMode(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for dangerous capabilities
	if f := s.checkCapabilities(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for mounted Docker socket
	if f := s.checkDockerSocketMount(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for host namespace sharing
	if f := s.checkHostNamespaces(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for sensitive mounts
	if f := s.checkSensitiveMounts(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for container escape binaries
	if f := s.checkEscapeBinaries(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.Logger().Debug("container security scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *ContainerScanner) isInsideContainer() bool {
	// Check for .dockerenv file
	if s.FileExists("/.dockerenv") {
		return true
	}

	// Check cgroup for docker/container indicators
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		content := string(data)
		if strings.Contains(content, "docker") ||
			strings.Contains(content, "kubepods") ||
			strings.Contains(content, "containerd") ||
			strings.Contains(content, "lxc") {
			return true
		}
	}

	// Check for container runtime environment variables
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" ||
		os.Getenv("container") != "" {
		return true
	}

	return false
}

func (s *ContainerScanner) checkPrivilegedMode(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check if we have all capabilities (indicates privileged mode)
	capData, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}

	for _, line := range strings.Split(string(capData), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			capValue := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			// 0000003fffffffff is all capabilities on modern kernels
			if capValue == "0000003fffffffff" || capValue == "000001ffffffffff" {
				findings = append(findings, entity.NewFinding(
					entity.CategoryPersistence,
					entity.SeverityCritical,
					"Container running in privileged mode",
					"Container has all capabilities enabled - trivial escape possible",
				).WithDetail("effective_caps", capValue).
					WithDetail("technique", "T1611 - Escape to Host").
					WithDetail("risk", "Attacker can escape to host with full root access"))
			}
		}
	}

	// Also check if /dev is fully populated (privileged indicator)
	devEntries, err := os.ReadDir("/dev")
	if err == nil && len(devEntries) > 50 {
		// Check for specific dangerous devices
		dangerousDevices := []string{"sda", "sdb", "nvme", "mem", "kmem"}
		for _, dev := range devEntries {
			for _, dangerous := range dangerousDevices {
				if strings.HasPrefix(dev.Name(), dangerous) {
					findings = append(findings, entity.NewFinding(
						entity.CategoryPersistence,
						entity.SeverityCritical,
						"Raw device access in container",
						"Container has access to host block devices",
					).WithDetail("device", dev.Name()).
						WithDetail("risk", "Direct host disk access enables escape"))
					break
				}
			}
		}
	}

	return findings
}

func (s *ContainerScanner) checkCapabilities(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Read current process capabilities
	capData, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}

	var capEffective, capPermitted, capBounding string
	for _, line := range strings.Split(string(capData), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			capEffective = strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		} else if strings.HasPrefix(line, "CapPrm:") {
			capPermitted = strings.TrimSpace(strings.TrimPrefix(line, "CapPrm:"))
		} else if strings.HasPrefix(line, "CapBnd:") {
			capBounding = strings.TrimSpace(strings.TrimPrefix(line, "CapBnd:"))
		}
	}

	// Use capsh if available for human-readable output
	output, err := s.ExecCommand(ctx, "capsh", "--print")
	if err == nil {
		for capName, description := range dangerousCapabilities {
			if strings.Contains(output, strings.ToLower(capName)) ||
				strings.Contains(output, capName) {
				findings = append(findings, entity.NewFinding(
					entity.CategoryPersistence,
					entity.SeverityHigh,
					"Dangerous capability detected",
					description,
				).WithDetail("capability", capName).
					WithDetail("cap_effective", capEffective).
					WithDetail("cap_permitted", capPermitted).
					WithDetail("cap_bounding", capBounding))
			}
		}
	}

	return findings
}

func (s *ContainerScanner) checkDockerSocketMount(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	socketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/containerd/containerd.sock",
	}

	for _, socketPath := range socketPaths {
		if s.FileExists(socketPath) {
			// Check if socket is writable
			file, err := os.OpenFile(socketPath, os.O_WRONLY, 0)
			writable := err == nil
			if file != nil {
				file.Close()
			}

			severity := entity.SeverityHigh
			if writable {
				severity = entity.SeverityCritical
			}

			findings = append(findings, entity.NewFinding(
				entity.CategoryPersistence,
				severity,
				"Container runtime socket mounted",
				"Container has access to Docker/containerd socket",
			).WithDetail("socket_path", socketPath).
				WithDetail("writable", writable).
				WithDetail("technique", "T1611 - Escape to Host").
				WithDetail("risk", "Full control over container runtime enables host escape"))
		}
	}

	return findings
}

func (s *ContainerScanner) checkHostNamespaces(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check PID namespace (host PID = can see/signal host processes)
	// Note: PID namespace check is informational - actual escape detection
	// happens below when checking for visible host processes
	_, _ = os.Readlink("/proc/1/ns/pid")     // Read PID 1 namespace
	_, _ = os.Readlink("/proc/self/ns/pid")  // Read self namespace

	// Check if we can see host processes
	output, err := s.ExecCommand(ctx, "ps", "aux")
	if err == nil {
		// If we can see systemd, dockerd, or many root processes, likely host PID
		if strings.Contains(output, "systemd") ||
			strings.Contains(output, "dockerd") ||
			strings.Contains(output, "containerd-shim") {
			findings = append(findings, entity.NewFinding(
				entity.CategoryPersistence,
				entity.SeverityCritical,
				"Container sharing host PID namespace",
				"Container can see and interact with host processes",
			).WithDetail("technique", "T1611 - Escape to Host").
				WithDetail("risk", "Can attach to host processes, inject code, or escalate privileges"))
		}
	}

	// Check network namespace
	interfaces, err := s.RunCommand(ctx, "ip", "addr")
	if err == nil {
		// Check for host-only interfaces like docker0, br-*
		for _, line := range interfaces {
			if strings.Contains(line, "docker0") ||
				strings.Contains(line, "br-") ||
				strings.Contains(line, "virbr") {
				findings = append(findings, entity.NewFinding(
					entity.CategoryPersistence,
					entity.SeverityHigh,
					"Container sharing host network namespace",
					"Container has access to host network interfaces",
				).WithDetail("technique", "T1611 - Escape to Host").
					WithDetail("risk", "Can intercept host network traffic and access host services"))
				break
			}
		}
	}

	return findings
}

func (s *ContainerScanner) checkSensitiveMounts(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Read /proc/mounts to check mounted filesystems
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return nil
	}

	sensitiveMounts := []struct {
		path     string
		severity entity.Severity
		reason   string
	}{
		{"/etc", entity.SeverityHigh, "Host /etc mounted - can modify system configuration"},
		{"/root", entity.SeverityCritical, "Host /root mounted - access to root user files"},
		{"/home", entity.SeverityHigh, "Host /home mounted - access to user data"},
		{"/proc/sys", entity.SeverityCritical, "Kernel parameters writable - can modify kernel settings"},
		{"/sys/fs/cgroup", entity.SeverityHigh, "Cgroup filesystem - can escape via cgroup release_agent"},
		{"type cgroup (rw", entity.SeverityHigh, "Writable cgroup mount - potential escape vector"},
	}

	mountContent := string(mounts)
	for _, mount := range sensitiveMounts {
		if strings.Contains(mountContent, mount.path) {
			findings = append(findings, entity.NewFinding(
				entity.CategoryPersistence,
				mount.severity,
				"Sensitive host path mounted",
				mount.reason,
			).WithDetail("mount_pattern", mount.path).
				WithDetail("technique", "T1611 - Escape to Host"))
		}
	}

	// Check for writable /proc/sys/kernel (extremely dangerous)
	if s.FileExists("/proc/sys/kernel/core_pattern") {
		testFile, err := os.OpenFile("/proc/sys/kernel/core_pattern", os.O_WRONLY, 0)
		if err == nil {
			testFile.Close()
			findings = append(findings, entity.NewFinding(
				entity.CategoryPersistence,
				entity.SeverityCritical,
				"Kernel core_pattern is writable",
				"Can write to core_pattern for code execution escape",
			).WithDetail("path", "/proc/sys/kernel/core_pattern").
				WithDetail("technique", "T1611 - Escape to Host").
				WithDetail("risk", "Classic container escape via core_pattern overwrite"))
		}
	}

	return findings
}

func (s *ContainerScanner) checkEscapeBinaries(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check for binaries that could aid escape
	escapeBinaries := []struct {
		path   string
		reason string
	}{
		{"/usr/bin/docker", "Docker client in container"},
		{"/usr/bin/kubectl", "Kubernetes client in container"},
		{"/usr/bin/crictl", "CRI client in container"},
		{"/usr/bin/nsenter", "Namespace manipulation tool"},
		{"/usr/bin/unshare", "Namespace creation tool"},
	}

	for _, binary := range escapeBinaries {
		if s.FileExists(binary.path) {
			findings = append(findings, entity.NewFinding(
				entity.CategoryPersistence,
				entity.SeverityMedium,
				"Container escape tool present",
				binary.reason,
			).WithDetail("binary", binary.path).
				WithDetail("risk", "Could be used to escape container or access other containers"))
		}
	}

	return findings
}

func (s *ContainerScanner) checkExposedDockerSockets(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check for world-readable Docker socket on host
	socketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
	}

	for _, socketPath := range socketPaths {
		info, err := os.Stat(socketPath)
		if err != nil {
			continue
		}

		mode := info.Mode()
		// Check if socket is world-accessible
		if mode.Perm()&0006 != 0 {
			findings = append(findings, entity.NewFinding(
				entity.CategoryPersistence,
				entity.SeverityCritical,
				"Docker socket is world-accessible",
				"Any user can control Docker daemon",
			).WithDetail("socket_path", socketPath).
				WithDetail("permissions", mode.String()).
				WithDetail("risk", "Local privilege escalation to root"))
		}
	}

	// Check for Docker daemon running with insecure options
	output, err := s.ExecCommand(ctx, "ps", "aux")
	if err == nil {
		// Check for dangerous Docker daemon flags
		dangerousFlags := []struct {
			pattern *regexp.Regexp
			reason  string
		}{
			{regexp.MustCompile(`dockerd.*--privileged`), "Docker daemon with privileged flag"},
			{regexp.MustCompile(`dockerd.*-H\s*tcp://`), "Docker daemon exposed on TCP"},
			{regexp.MustCompile(`dockerd.*--insecure-registry`), "Docker daemon allows insecure registries"},
		}

		for _, flag := range dangerousFlags {
			if flag.pattern.MatchString(output) {
				findings = append(findings, entity.NewFinding(
					entity.CategoryPersistence,
					entity.SeverityHigh,
					"Docker daemon running with insecure options",
					flag.reason,
				).WithDetail("pattern", flag.pattern.String()))
			}
		}
	}

	return findings
}
