package platform

import (
	"bufio"
	"context"
	"os/exec"
	"strconv"
	"strings"
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
	tools := []string{}

	toolList := []string{
		"powershell",
		"cmd",
		"netstat",
		"tasklist",
		"wmic",
		"schtasks",
		"reg",
		"icacls",
		"sc",
		"whoami",
		"net",
	}

	for _, tool := range toolList {
		if commandExists(tool) {
			tools = append(tools, tool)
		}
	}

	return tools
}

func (s *WindowsStrategy) SupportedScanners() []string {
	return []string{
		"network",
		"process",
		"filesystem",
		"user",
		"ssh",
		"persistence", // Registry, scheduled tasks, services
	}
}

func (s *WindowsStrategy) ExecuteCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (s *WindowsStrategy) GetUserCrontab(ctx context.Context) ([]string, error) {
	// Windows uses Task Scheduler instead of cron
	// Return scheduled tasks for the current user
	tasks, err := s.GetScheduledTasks(ctx)
	if err != nil {
		return nil, err
	}

	var lines []string
	for _, task := range tasks {
		// Format similar to crontab output
		line := task.Name + " | " + task.State + " | " + strings.Join(task.Actions, ", ")
		lines = append(lines, line)
	}

	return lines, nil
}

func (s *WindowsStrategy) GetSystemServices(ctx context.Context) ([]ServiceInfo, error) {
	var services []ServiceInfo

	// Use sc query to list all services
	output, err := s.ExecuteCommand(ctx, "sc", "query", "type=", "service", "state=", "all")
	if err != nil {
		// Fallback to wmic
		return s.getServicesViaWMIC(ctx)
	}

	services = parseScQueryOutput(output)
	return services, nil
}

func (s *WindowsStrategy) getServicesViaWMIC(ctx context.Context) ([]ServiceInfo, error) {
	var services []ServiceInfo

	output, err := s.ExecuteCommand(ctx, "wmic", "service", "get", "Name,State,StartMode", "/format:csv")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node,") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 4 {
			services = append(services, ServiceInfo{
				Name:    fields[1],
				Status:  fields[3],
				Enabled: strings.ToLower(fields[2]) == "auto",
				Type:    "windows-service",
			})
		}
	}

	return services, nil
}

func parseScQueryOutput(output string) []ServiceInfo {
	var services []ServiceInfo
	var currentService *ServiceInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "SERVICE_NAME:") {
			if currentService != nil {
				services = append(services, *currentService)
			}
			currentService = &ServiceInfo{
				Name: strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:")),
				Type: "windows-service",
			}
		} else if currentService != nil {
			if strings.HasPrefix(line, "STATE") {
				// Format: STATE : 4  RUNNING
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					stateParts := strings.Fields(parts[1])
					if len(stateParts) >= 2 {
						currentService.Status = stateParts[1]
						currentService.Enabled = stateParts[1] == "RUNNING"
					}
				}
			}
		}
	}

	if currentService != nil {
		services = append(services, *currentService)
	}

	return services
}

func (s *WindowsStrategy) GetNetworkConnections(ctx context.Context) ([]ConnectionInfo, error) {
	var connections []ConnectionInfo

	// Use netstat with -ano for all connections with PIDs
	output, err := s.ExecuteCommand(ctx, "netstat", "-ano")
	if err != nil {
		return nil, err
	}

	connections = parseWindowsNetstatOutput(output)

	// Enrich with process names
	processes, _ := s.GetProcessList(ctx)
	pidToName := make(map[int]string)
	for _, p := range processes {
		pidToName[p.PID] = p.Name
	}

	for i := range connections {
		if name, ok := pidToName[connections[i].PID]; ok {
			connections[i].ProcessName = name
		}
	}

	return connections, nil
}

func parseWindowsNetstatOutput(output string) []ConnectionInfo {
	var connections []ConnectionInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)

		// Skip headers and empty lines
		if len(fields) < 4 {
			continue
		}

		protocol := strings.ToLower(fields[0])
		if protocol != "tcp" && protocol != "udp" {
			continue
		}

		conn := ConnectionInfo{
			Protocol: protocol,
		}

		// Parse local address
		localAddr := fields[1]
		if idx := strings.LastIndex(localAddr, ":"); idx != -1 {
			conn.LocalAddr = localAddr[:idx]
			conn.LocalPort, _ = strconv.Atoi(localAddr[idx+1:])
		}

		// Parse foreign/remote address
		remoteAddr := fields[2]
		if idx := strings.LastIndex(remoteAddr, ":"); idx != -1 {
			conn.RemoteAddr = remoteAddr[:idx]
			conn.RemotePort, _ = strconv.Atoi(remoteAddr[idx+1:])
		}

		// Parse state and PID
		if protocol == "tcp" {
			if len(fields) >= 4 {
				conn.State = fields[3]
			}
			if len(fields) >= 5 {
				conn.PID, _ = strconv.Atoi(fields[4])
			}
		} else {
			// UDP doesn't have state
			conn.State = "STATELESS"
			if len(fields) >= 4 {
				conn.PID, _ = strconv.Atoi(fields[3])
			}
		}

		connections = append(connections, conn)
	}

	return connections
}

func (s *WindowsStrategy) GetProcessList(ctx context.Context) ([]ProcessInfo, error) {
	var processes []ProcessInfo

	// Use tasklist with verbose output
	output, err := s.ExecuteCommand(ctx, "tasklist", "/fo", "csv", "/v")
	if err != nil {
		// Fallback to basic tasklist
		return s.getProcessListBasic(ctx)
	}

	processes = parseTasklistCSV(output)

	// Enrich with PPID from wmic if available
	s.enrichProcessPPID(ctx, processes)

	return processes, nil
}

func (s *WindowsStrategy) getProcessListBasic(ctx context.Context) ([]ProcessInfo, error) {
	var processes []ProcessInfo

	output, err := s.ExecuteCommand(ctx, "tasklist", "/fo", "csv")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines[1:] { // Skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := parseCSVLine(line)
		if len(fields) >= 2 {
			pid, _ := strconv.Atoi(strings.Trim(fields[1], "\""))
			processes = append(processes, ProcessInfo{
				PID:  pid,
				Name: strings.Trim(fields[0], "\""),
			})
		}
	}

	return processes, nil
}

func parseTasklistCSV(output string) []ProcessInfo {
	var processes []ProcessInfo

	lines := strings.Split(output, "\n")
	for _, line := range lines[1:] { // Skip header
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := parseCSVLine(line)
		if len(fields) >= 2 {
			pid, _ := strconv.Atoi(strings.Trim(fields[1], "\""))
			proc := ProcessInfo{
				PID:  pid,
				Name: strings.Trim(fields[0], "\""),
			}

			// Username is in field 6 if available
			if len(fields) >= 7 {
				proc.User = strings.Trim(fields[6], "\"")
			}

			processes = append(processes, proc)
		}
	}

	return processes
}

func (s *WindowsStrategy) enrichProcessPPID(ctx context.Context, processes []ProcessInfo) {
	// Use wmic to get PPID information
	output, err := s.ExecuteCommand(ctx, "wmic", "process", "get", "ProcessId,ParentProcessId", "/format:csv")
	if err != nil {
		return
	}

	ppidMap := make(map[int]int)
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node,") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 3 {
			ppid, _ := strconv.Atoi(fields[1])
			pid, _ := strconv.Atoi(fields[2])
			ppidMap[pid] = ppid
		}
	}

	for i := range processes {
		if ppid, ok := ppidMap[processes[i].PID]; ok {
			processes[i].PPID = ppid
		}
	}
}

func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false

	for _, r := range line {
		switch r {
		case '"':
			inQuotes = !inQuotes
			current.WriteRune(r)
		case ',':
			if inQuotes {
				current.WriteRune(r)
			} else {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		fields = append(fields, current.String())
	}

	return fields
}

// Windows-specific methods

// GetScheduledTasks returns Windows scheduled tasks
func (s *WindowsStrategy) GetScheduledTasks(ctx context.Context) ([]ScheduledTask, error) {
	var tasks []ScheduledTask

	// Use schtasks to query scheduled tasks
	output, err := s.ExecuteCommand(ctx, "schtasks", "/query", "/fo", "csv", "/v")
	if err != nil {
		return nil, err
	}

	tasks = parseScheduledTasksCSV(output)
	return tasks, nil
}

func parseScheduledTasksCSV(output string) []ScheduledTask {
	var tasks []ScheduledTask

	lines := strings.Split(output, "\n")
	var headerMap map[string]int

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := parseCSVLine(line)

		// First line is header
		if i == 0 || headerMap == nil {
			headerMap = make(map[string]int)
			for j, field := range fields {
				headerMap[strings.Trim(field, "\"")] = j
			}
			continue
		}

		task := ScheduledTask{}

		if idx, ok := headerMap["TaskName"]; ok && idx < len(fields) {
			task.Name = strings.Trim(fields[idx], "\"")
		}
		if idx, ok := headerMap["Task To Run"]; ok && idx < len(fields) {
			task.Actions = []string{strings.Trim(fields[idx], "\"")}
		}
		if idx, ok := headerMap["Status"]; ok && idx < len(fields) {
			task.State = strings.Trim(fields[idx], "\"")
		}
		if idx, ok := headerMap["Next Run Time"]; ok && idx < len(fields) {
			task.NextRunTime = strings.Trim(fields[idx], "\"")
		}
		if idx, ok := headerMap["Last Run Time"]; ok && idx < len(fields) {
			task.LastRunTime = strings.Trim(fields[idx], "\"")
		}
		if idx, ok := headerMap["Scheduled Task State"]; ok && idx < len(fields) {
			task.State = strings.Trim(fields[idx], "\"")
		}

		// Skip system folder tasks unless they have interesting paths
		if task.Name != "" && !strings.HasPrefix(task.Name, "\\Microsoft\\Windows\\") {
			tasks = append(tasks, task)
		}
	}

	return tasks
}

// GetRegistryStartup returns startup entries from Windows registry
func (s *WindowsStrategy) GetRegistryStartup(ctx context.Context) ([]RegistryEntry, error) {
	var entries []RegistryEntry

	// Common startup registry locations
	startupKeys := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
	}

	for _, key := range startupKeys {
		keyEntries, err := s.queryRegistryKey(ctx, key)
		if err != nil {
			continue // Skip keys we can't access
		}
		entries = append(entries, keyEntries...)
	}

	return entries, nil
}

func (s *WindowsStrategy) queryRegistryKey(ctx context.Context, key string) ([]RegistryEntry, error) {
	var entries []RegistryEntry

	output, err := s.ExecuteCommand(ctx, "reg", "query", key)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "HK") {
			continue
		}

		// Format: Name    REG_TYPE    Value
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			entry := RegistryEntry{
				Key:   key,
				Name:  fields[0],
				Type:  fields[1],
				Value: strings.Join(fields[2:], " "),
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// GetWindowsServices returns Windows services with detailed info
func (s *WindowsStrategy) GetWindowsServices(ctx context.Context) ([]WindowsService, error) {
	var services []WindowsService

	// Use wmic for detailed service information
	output, err := s.ExecuteCommand(ctx, "wmic", "service", "get",
		"Name,DisplayName,State,StartMode,PathName,StartName", "/format:csv")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node,") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) >= 7 {
			service := WindowsService{
				DisplayName: fields[1],
				Name:        fields[2],
				BinaryPath:  fields[3],
				Account:     fields[4],
				StartType:   fields[5],
				State:       fields[6],
			}
			services = append(services, service)
		}
	}

	return services, nil
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
