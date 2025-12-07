package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// WindowsMemoryScanner detects process injection, hollowing, and memory anomalies on Windows
type WindowsMemoryScanner struct {
	BaseScanner
}

// Known malicious process names and patterns
var (
	// Processes commonly targeted for injection (reserved for injection detection enhancement)
	_ = []string{
		"explorer.exe",
		"svchost.exe",
		"services.exe",
		"lsass.exe",
		"winlogon.exe",
		"csrss.exe",
		"smss.exe",
		"wininit.exe",
		"spoolsv.exe",
		"taskhost.exe",
		"taskhostw.exe",
		"RuntimeBroker.exe",
		"dllhost.exe",
		"conhost.exe",
		"sihost.exe",
	}

	// Suspicious parent-child relationships
	suspiciousParentChild = map[string][]string{
		"winword.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
		"excel.exe":     {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
		"outlook.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
		"powerpnt.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
		"acrobat.exe":   {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
		"acrord32.exe":  {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
		"notepad.exe":   {"cmd.exe", "powershell.exe"},
		"mshta.exe":     {"cmd.exe", "powershell.exe"},
		"wscript.exe":   {"cmd.exe", "powershell.exe"},
		"cscript.exe":   {"cmd.exe", "powershell.exe"},
	}

	// Processes that should only have specific parents - comprehensive list
	validParents = map[string][]string{
		// Core system processes
		"smss.exe":      {"System"},
		"csrss.exe":     {"smss.exe"},
		"wininit.exe":   {"smss.exe"},
		"winlogon.exe":  {"smss.exe"},
		"services.exe":  {"wininit.exe"},
		"lsass.exe":     {"wininit.exe"},
		"lsaiso.exe":    {"wininit.exe"},
		// Service host processes
		"svchost.exe":   {"services.exe", "MsMpEng.exe"},
		// Runtime and UI processes
		"RuntimeBroker.exe":  {"svchost.exe"},
		"dllhost.exe":        {"svchost.exe", "services.exe"},
		"sihost.exe":         {"svchost.exe"},
		"taskhostw.exe":      {"svchost.exe"},
		"fontdrvhost.exe":    {"wininit.exe", "winlogon.exe"},
		"dwm.exe":            {"winlogon.exe"},
		// Search processes
		"SearchIndexer.exe":  {"services.exe"},
		"SearchApp.exe":      {"svchost.exe"},
		"SearchUI.exe":       {"svchost.exe"},
		"SearchHost.exe":     {"svchost.exe"},
		// Windows components
		"spoolsv.exe":        {"services.exe"},
		"WmiPrvSE.exe":       {"svchost.exe"},
		"msdtc.exe":          {"services.exe"},
		"VaultSvc.exe":       {"services.exe"},
		// Security processes
		"SecurityHealthService.exe": {"services.exe"},
		"MsMpEng.exe":        {"services.exe"},
	}

	// Suspicious command line patterns - comprehensive detection
	suspiciousCmdPatterns = []struct {
		pattern     *regexp.Regexp
		description string
		severity    entity.Severity
	}{
		// PowerShell abuse
		{regexp.MustCompile(`(?i)powershell.*-enc`), "Encoded PowerShell", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)powershell.*frombase64`), "Base64 decode in PowerShell", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)powershell.*downloadstring`), "PowerShell download", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)powershell.*-w\s*hidden`), "Hidden PowerShell", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*-nop`), "No-profile PowerShell", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)powershell.*bypass`), "Bypass execution policy", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*\bIEX\b`), "PowerShell IEX", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*invoke-expression`), "PowerShell Invoke-Expression", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*\[System\.Net\.WebClient\]`), "PowerShell WebClient", entity.SeverityHigh},
		// LOLBins
		{regexp.MustCompile(`(?i)cmd.*/c.*powershell`), "CMD spawning PowerShell", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)mshta.*vbscript`), "MSHTA VBScript", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)mshta.*javascript`), "MSHTA JavaScript", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)mshta.*http`), "MSHTA remote HTA", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)regsvr32.*/s.*/n`), "Regsvr32 scriptlet", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)regsvr32.*http`), "Regsvr32 remote COM", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)rundll32.*javascript`), "Rundll32 JavaScript", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)rundll32.*vbscript`), "Rundll32 VBScript", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)cmstp.*/s`), "CMSTP INF execution", entity.SeverityCritical},
		// Download/transfer utilities
		{regexp.MustCompile(`(?i)certutil.*-urlcache`), "Certutil download", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)certutil.*-decode`), "Certutil decode", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)bitsadmin.*transfer`), "BITS download", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)curl\.exe.*http`), "Curl download", entity.SeverityMedium},
		// WMI abuse
		{regexp.MustCompile(`(?i)wmic.*process.*call.*create`), "WMIC process create", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)wmic.*/node:`), "WMIC remote execution", entity.SeverityCritical},
		// Persistence
		{regexp.MustCompile(`(?i)net\s+user.*/add`), "Adding user account", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)net\s+localgroup.*admin.*/add`), "Adding to admin group", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)schtasks.*/create`), "Creating scheduled task", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)reg.*add.*\\run`), "Adding Run key", entity.SeverityHigh},
		// Defense evasion / destruction
		{regexp.MustCompile(`(?i)vssadmin.*delete.*shadows`), "Deleting shadow copies", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)bcdedit.*/set.*recoveryenabled.*no`), "Disabling recovery", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)wbadmin.*delete`), "Deleting backups", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)wevtutil.*cl`), "Clearing event logs", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)sc.*config.*start.*disabled`), "Disabling service", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)netsh.*firewall.*disable`), "Disabling firewall", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)netsh.*advfirewall.*off`), "Disabling firewall", entity.SeverityCritical},
		// Credential dumping
		{regexp.MustCompile(`(?i)mimikatz`), "Mimikatz detected", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)sekurlsa`), "Credential dumping (sekurlsa)", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)procdump.*-ma.*lsass`), "LSASS memory dump", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)procdump.*lsass\.exe`), "LSASS dump via procdump", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)comsvcs\.dll.*MiniDump`), "Comsvcs.dll minidump", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)ntdsutil.*ifm`), "NTDS.dit extraction", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)ntdsutil.*"ac.*ntds"`), "NTDS.dit extraction", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)secretsdump`), "Impacket secretsdump", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)pypykatz`), "Pypykatz credential dump", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)lazagne`), "LaZagne credential harvester", entity.SeverityCritical},
		// Reconnaissance
		{regexp.MustCompile(`(?i)nltest.*/dclist`), "Domain controller enumeration", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)nltest.*/domain_trusts`), "Domain trust enumeration", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)dsquery.*computer`), "AD computer enumeration", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)net\s+group.*"domain admins"`), "Domain admin enumeration", entity.SeverityMedium},
	}

	// Known malicious process names (often typosquatting)
	maliciousProcessPatterns = []struct {
		pattern     *regexp.Regexp
		description string
	}{
		{regexp.MustCompile(`(?i)^svch0st\.exe$`), "svchost typosquat with 0"},
		{regexp.MustCompile(`(?i)^scvhost\.exe$`), "svchost typosquat"},
		{regexp.MustCompile(`(?i)^svchosts\.exe$`), "svchost typosquat with s"},
		{regexp.MustCompile(`(?i)^lsasss\.exe$`), "lsass typosquat"},
		{regexp.MustCompile(`(?i)^lsas\.exe$`), "lsass typosquat"},
		{regexp.MustCompile(`(?i)^csrsss\.exe$`), "csrss typosquat"},
		{regexp.MustCompile(`(?i)^cssrs\.exe$`), "csrss typosquat"},
		{regexp.MustCompile(`(?i)^exp1orer\.exe$`), "explorer typosquat"},
		{regexp.MustCompile(`(?i)^explore\.exe$`), "explorer typosquat"},
		{regexp.MustCompile(`(?i)^taskh0st\.exe$`), "taskhost typosquat"},
	}
)

func NewWindowsMemoryScanner() *WindowsMemoryScanner {
	return &WindowsMemoryScanner{
		BaseScanner: NewBaseScanner("windows-memory", "Windows process injection and memory anomaly detector"),
	}
}

func (s *WindowsMemoryScanner) Category() entity.FindingCategory {
	return entity.CategoryProcess
}

func (s *WindowsMemoryScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting Windows memory and process scan")
	var findings []*entity.Finding

	// Get process list with details
	processes, err := s.getProcessList(ctx)
	if err != nil {
		s.log.Debug("failed to get process list", zap.Error(err))
		return nil, err
	}

	// Check for suspicious parent-child relationships
	if f := s.checkParentChildRelationships(ctx, processes); f != nil {
		findings = append(findings, f...)
	}

	// Check for process name spoofing/typosquatting
	if f := s.checkProcessNameSpoofing(ctx, processes); f != nil {
		findings = append(findings, f...)
	}

	// Check for suspicious command lines
	if f := s.checkSuspiciousCommandLines(ctx, processes); f != nil {
		findings = append(findings, f...)
	}

	// Check for processes running from suspicious locations
	if f := s.checkSuspiciousLocations(ctx, processes); f != nil {
		findings = append(findings, f...)
	}

	// Check for hollow processes (mismatched image)
	if f := s.checkHollowProcesses(ctx, processes); f != nil {
		findings = append(findings, f...)
	}

	// Check for multiple instances of singleton processes
	if f := s.checkSingletonProcesses(ctx, processes); f != nil {
		findings = append(findings, f...)
	}

	// Check for processes with suspicious privileges
	if f := s.checkSuspiciousPrivileges(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for unsigned/suspicious DLLs loaded
	if f := s.checkLoadedModules(ctx, processes); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("Windows memory scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

type windowsProcess struct {
	PID         int
	PPID        int
	Name        string
	CommandLine string
	ImagePath   string
	User        string
	SessionID   int
}

func (s *WindowsMemoryScanner) getProcessList(ctx context.Context) ([]windowsProcess, error) {
	// Try PowerShell first (modern approach, works on Windows 11+)
	processes, err := s.getProcessListPowerShell(ctx)
	if err == nil && len(processes) > 0 {
		return processes, nil
	}

	// Fallback to WMIC (for older Windows)
	return s.getProcessListWMIC(ctx)
}

// getProcessListPowerShell gets process list using PowerShell (preferred for Windows 11+)
func (s *WindowsMemoryScanner) getProcessListPowerShell(ctx context.Context) ([]windowsProcess, error) {
	script := `Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,SessionId | ConvertTo-Csv -NoTypeInformation`
	output, err := s.ExecCommand(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil, err
	}

	var processes []windowsProcess
	lines := strings.Split(output, "\n")

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 { // Skip header
			continue
		}

		fields := parseCSVLineForWindows(line)
		if len(fields) < 6 {
			continue
		}

		proc := windowsProcess{
			Name:        strings.Trim(fields[2], "\""),
			CommandLine: strings.Trim(fields[3], "\""),
			ImagePath:   strings.Trim(fields[4], "\""),
		}
		proc.PID, _ = strconv.Atoi(strings.Trim(fields[0], "\""))
		proc.PPID, _ = strconv.Atoi(strings.Trim(fields[1], "\""))
		proc.SessionID, _ = strconv.Atoi(strings.Trim(fields[5], "\""))

		processes = append(processes, proc)
	}

	return processes, nil
}

// getProcessListWMIC gets process list using WMIC (fallback for older Windows)
func (s *WindowsMemoryScanner) getProcessListWMIC(ctx context.Context) ([]windowsProcess, error) {
	var processes []windowsProcess

	output, err := s.ExecCommand(ctx, "wmic", "process", "get",
		"ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,SessionId",
		"/format:csv")
	if err != nil {
		// Fallback to tasklist
		return s.getProcessListFallback(ctx)
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Node,") {
			continue
		}

		fields := strings.Split(line, ",")
		if len(fields) < 7 {
			continue
		}

		// CSV order: Node,CommandLine,ExecutablePath,Name,ParentProcessId,ProcessId,SessionId
		proc := windowsProcess{
			CommandLine: fields[1],
			ImagePath:   fields[2],
			Name:        fields[3],
		}
		proc.PPID, _ = strconv.Atoi(fields[4])
		proc.PID, _ = strconv.Atoi(fields[5])
		proc.SessionID, _ = strconv.Atoi(fields[6])

		processes = append(processes, proc)
	}

	return processes, nil
}

func (s *WindowsMemoryScanner) getProcessListFallback(ctx context.Context) ([]windowsProcess, error) {
	var processes []windowsProcess

	output, err := s.ExecCommand(ctx, "tasklist", "/fo", "csv", "/v")
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := parseCSVLineForWindows(line)
		if len(fields) >= 2 {
			pid, _ := strconv.Atoi(strings.Trim(fields[1], "\""))
			proc := windowsProcess{
				PID:  pid,
				Name: strings.Trim(fields[0], "\""),
			}
			if len(fields) >= 7 {
				proc.User = strings.Trim(fields[6], "\"")
			}
			processes = append(processes, proc)
		}
	}

	return processes, nil
}

func (s *WindowsMemoryScanner) checkParentChildRelationships(ctx context.Context, processes []windowsProcess) []*entity.Finding {
	var findings []*entity.Finding

	// Build PID to process map
	pidMap := make(map[int]windowsProcess)
	for _, proc := range processes {
		pidMap[proc.PID] = proc
	}

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		parentProc, hasParent := pidMap[proc.PPID]
		if !hasParent {
			continue
		}

		procNameLower := strings.ToLower(proc.Name)
		parentNameLower := strings.ToLower(parentProc.Name)

		// Check suspicious parent-child relationships
		if suspiciousChildren, ok := suspiciousParentChild[parentNameLower]; ok {
			for _, child := range suspiciousChildren {
				if strings.ToLower(child) == procNameLower {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winmem-parentchild-%d", proc.PID),
						Category:    entity.CategoryProcess,
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious parent-child process relationship",
						Description: fmt.Sprintf("%s spawned suspicious child %s", parentProc.Name, proc.Name),
						Path:        proc.ImagePath,
						Details: map[string]interface{}{
							"child_pid":     proc.PID,
							"child_name":    proc.Name,
							"child_cmdline": proc.CommandLine,
							"parent_pid":    proc.PPID,
							"parent_name":   parentProc.Name,
							"technique":     "T1059 - Command and Scripting Interpreter",
						},
					})
				}
			}
		}

		// Check for system processes with wrong parents
		if validParentList, ok := validParents[procNameLower]; ok {
			isValidParent := false
			for _, validParent := range validParentList {
				if strings.EqualFold(parentProc.Name, validParent) {
					isValidParent = true
					break
				}
			}
			if !isValidParent && proc.PPID != 0 {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winmem-wrongparent-%d", proc.PID),
					Category:    entity.CategoryProcess,
					Severity:    entity.SeverityCritical,
					Title:       "System process with unexpected parent",
					Description: fmt.Sprintf("%s has unexpected parent %s (expected: %v)", proc.Name, parentProc.Name, validParentList),
					Path:        proc.ImagePath,
					Details: map[string]interface{}{
						"process_pid":     proc.PID,
						"process_name":    proc.Name,
						"actual_parent":   parentProc.Name,
						"expected_parents": validParentList,
						"risk":            "Possible process injection or masquerading",
					},
				})
			}
		}
	}

	return findings
}

func (s *WindowsMemoryScanner) checkProcessNameSpoofing(ctx context.Context, processes []windowsProcess) []*entity.Finding {
	var findings []*entity.Finding

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		for _, pattern := range maliciousProcessPatterns {
			if pattern.pattern.MatchString(proc.Name) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winmem-typosquat-%d", proc.PID),
					Category:    entity.CategoryProcess,
					Severity:    entity.SeverityCritical,
					Title:       "Process name typosquatting detected",
					Description: pattern.description,
					Path:        proc.ImagePath,
					Details: map[string]interface{}{
						"pid":         proc.PID,
						"name":        proc.Name,
						"image_path":  proc.ImagePath,
						"commandline": proc.CommandLine,
						"technique":   "T1036.005 - Masquerading: Match Legitimate Name or Location",
					},
				})
			}
		}
	}

	return findings
}

func (s *WindowsMemoryScanner) checkSuspiciousCommandLines(ctx context.Context, processes []windowsProcess) []*entity.Finding {
	var findings []*entity.Finding

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if proc.CommandLine == "" {
			continue
		}

		for _, pattern := range suspiciousCmdPatterns {
			if pattern.pattern.MatchString(proc.CommandLine) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winmem-cmdline-%d-%s", proc.PID, sanitizeID(pattern.description)),
					Category:    entity.CategoryProcess,
					Severity:    pattern.severity,
					Title:       "Suspicious command line detected",
					Description: pattern.description,
					Path:        proc.ImagePath,
					Details: map[string]interface{}{
						"pid":         proc.PID,
						"name":        proc.Name,
						"commandline": proc.CommandLine,
						"pattern":     pattern.description,
					},
				})
				break // Only report first matching pattern per process
			}
		}
	}

	return findings
}

func (s *WindowsMemoryScanner) checkSuspiciousLocations(ctx context.Context, processes []windowsProcess) []*entity.Finding {
	var findings []*entity.Finding

	suspiciousPaths := []string{
		`\temp\`,
		`\tmp\`,
		`\appdata\local\temp`,
		`\users\public\`,
		`\programdata\`,
		`\windows\temp\`,
		`\recycler\`,
		`\$recycle.bin\`,
		`\perflogs\`,
		`\windows\debug\`,
	}

	// System processes that should only run from System32
	system32Processes := map[string]bool{
		"svchost.exe":   true,
		"services.exe":  true,
		"lsass.exe":     true,
		"csrss.exe":     true,
		"smss.exe":      true,
		"wininit.exe":   true,
		"winlogon.exe":  true,
		"explorer.exe":  true,
	}

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if proc.ImagePath == "" {
			continue
		}

		pathLower := strings.ToLower(proc.ImagePath)

		// Check system processes running from wrong location
		if system32Processes[strings.ToLower(proc.Name)] {
			if !strings.Contains(pathLower, `\windows\system32\`) &&
				!strings.Contains(pathLower, `\windows\syswow64\`) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winmem-wrongloc-%d", proc.PID),
					Category:    entity.CategoryProcess,
					Severity:    entity.SeverityCritical,
					Title:       "System process running from wrong location",
					Description: fmt.Sprintf("%s running from non-system location", proc.Name),
					Path:        proc.ImagePath,
					Details: map[string]interface{}{
						"pid":           proc.PID,
						"name":          proc.Name,
						"image_path":    proc.ImagePath,
						"expected_path": `C:\Windows\System32\`,
						"technique":     "T1036.005 - Masquerading",
					},
				})
			}
		}

		// Check for any process in suspicious paths
		for _, susPath := range suspiciousPaths {
			if strings.Contains(pathLower, susPath) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winmem-suspath-%d", proc.PID),
					Category:    entity.CategoryProcess,
					Severity:    entity.SeverityMedium,
					Title:       "Process running from suspicious location",
					Description: fmt.Sprintf("Process running from %s", susPath),
					Path:        proc.ImagePath,
					Details: map[string]interface{}{
						"pid":        proc.PID,
						"name":       proc.Name,
						"image_path": proc.ImagePath,
						"sus_path":   susPath,
					},
				})
				break
			}
		}
	}

	return findings
}

func (s *WindowsMemoryScanner) checkHollowProcesses(ctx context.Context, processes []windowsProcess) []*entity.Finding {
	var findings []*entity.Finding

	// Process hollowing detection with improved heuristics to reduce false positives
	// Hollowed processes typically have mismatches between:
	// 1. Process name and the actual executable being run
	// 2. Image path and expected system locations
	// 3. Command line referencing a completely different executable

	// Processes that commonly have command lines not matching their names (not hollowing)
	legitimateMismatch := map[string]bool{
		"cmd.exe":            true, // Runs commands
		"powershell.exe":     true, // Runs scripts
		"pwsh.exe":           true, // PowerShell Core
		"conhost.exe":        true, // Console host
		"svchost.exe":        true, // Service host with -k flag
		"dllhost.exe":        true, // COM surrogate
		"wscript.exe":        true, // Script host
		"cscript.exe":        true, // Script host
		"mshta.exe":          true, // HTML application host
		"rundll32.exe":       true, // DLL execution
		"regsvr32.exe":       true, // COM registration
		"msiexec.exe":        true, // Installer
		"werfault.exe":       true, // Windows Error Reporting
		"wmiprvse.exe":       true, // WMI Provider
		"taskeng.exe":        true, // Task scheduler engine
		"taskhostw.exe":      true, // Task host window
		"backgroundtaskhost.exe": true, // UWP background tasks
		"runtimebroker.exe":  true, // Runtime broker
		"applicationframehost.exe": true, // UWP frame host
		"searchprotocolhost.exe": true, // Search protocol
		"searchfilterhost.exe": true, // Search filter
		"searchindexer.exe":  true, // Search indexer
		"smartscreen.exe":    true, // SmartScreen
		"consent.exe":        true, // UAC consent
	}

	// System processes that should ALWAYS run from System32/SysWOW64
	systemProcesses := map[string]bool{
		"lsass.exe":     true,
		"csrss.exe":     true,
		"smss.exe":      true,
		"services.exe":  true,
		"winlogon.exe":  true,
		"wininit.exe":   true,
	}

	for _, proc := range processes {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		nameLower := strings.ToLower(proc.Name)
		imagePathLower := strings.ToLower(proc.ImagePath)

		// Check 1: System processes running from wrong location (strong indicator)
		if systemProcesses[nameLower] && proc.ImagePath != "" {
			if !strings.Contains(imagePathLower, `\windows\system32\`) &&
				!strings.Contains(imagePathLower, `\windows\syswow64\`) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winmem-hollow-sysproc-%d", proc.PID),
					Category:    entity.CategoryProcess,
					Severity:    entity.SeverityCritical,
					Title:       "Critical system process running from wrong location",
					Description: fmt.Sprintf("%s should only run from System32", proc.Name),
					Path:        proc.ImagePath,
					Details: map[string]interface{}{
						"pid":           proc.PID,
						"name":          proc.Name,
						"image_path":    proc.ImagePath,
						"expected_path": `C:\Windows\System32\`,
						"technique":     "T1055.012 - Process Hollowing",
						"confidence":    "HIGH - System process from wrong location",
					},
				})
				continue
			}
		}

		// Skip processes known to have legitimate command line mismatches
		if legitimateMismatch[nameLower] {
			continue
		}

		// Skip if no command line or image path
		if proc.ImagePath == "" || proc.CommandLine == "" {
			continue
		}

		cmdLower := strings.ToLower(proc.CommandLine)

		// Check 2: Command line references a completely different executable
		// More sophisticated check: look for another .exe in the command line
		// that doesn't match the process name
		procBaseName := strings.TrimSuffix(nameLower, ".exe")

		// Look for .exe references in command line
		exePattern := regexp.MustCompile(`(?i)([a-z0-9_-]+)\.exe`)
		matches := exePattern.FindAllStringSubmatch(cmdLower, -1)

		suspiciousExeFound := false
		var suspiciousExe string
		for _, match := range matches {
			if len(match) >= 2 {
				exeName := match[1]
				// Check if this exe name is completely different from process name
				if exeName != procBaseName && exeName != "" {
					// Check if it's not just a path component containing the process
					if !strings.Contains(exeName, procBaseName) && !strings.Contains(procBaseName, exeName) {
						// Check for truly suspicious cases: known attack executables
						suspiciousExes := []string{"cmd", "powershell", "pwsh", "mshta", "wscript", "cscript"}
						for _, sus := range suspiciousExes {
							if exeName == sus && !legitimateMismatch[nameLower] {
								suspiciousExeFound = true
								suspiciousExe = match[0]
								break
							}
						}
					}
				}
			}
		}

		if suspiciousExeFound {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winmem-hollow-%d", proc.PID),
				Category:    entity.CategoryProcess,
				Severity:    entity.SeverityHigh,
				Title:       "Potential process hollowing detected",
				Description: fmt.Sprintf("Process %s appears to be running %s", proc.Name, suspiciousExe),
				Path:        proc.ImagePath,
				Details: map[string]interface{}{
					"pid":            proc.PID,
					"name":           proc.Name,
					"commandline":    proc.CommandLine,
					"image_path":     proc.ImagePath,
					"suspicious_exe": suspiciousExe,
					"technique":      "T1055.012 - Process Hollowing",
					"confidence":     "MEDIUM - Command line suggests different executable",
				},
			})
		}
	}

	return findings
}

func (s *WindowsMemoryScanner) checkSingletonProcesses(ctx context.Context, processes []windowsProcess) []*entity.Finding {
	var findings []*entity.Finding

	// Processes that should only have one instance
	singletonProcesses := map[string]bool{
		"lsass.exe":     true,
		"services.exe":  true,
		"smss.exe":      true,
		"csrss.exe":     false, // One per session, not truly singleton
		"wininit.exe":   true,
	}

	processCounts := make(map[string][]int)
	for _, proc := range processes {
		nameLower := strings.ToLower(proc.Name)
		if singletonProcesses[nameLower] {
			processCounts[nameLower] = append(processCounts[nameLower], proc.PID)
		}
	}

	for procName, pids := range processCounts {
		if len(pids) > 1 && singletonProcesses[procName] {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winmem-multiinstance-%s", procName),
				Category:    entity.CategoryProcess,
				Severity:    entity.SeverityCritical,
				Title:       "Multiple instances of singleton process",
				Description: fmt.Sprintf("Found %d instances of %s (should be 1)", len(pids), procName),
				Path:        procName,
				Details: map[string]interface{}{
					"process_name": procName,
					"instance_count": len(pids),
					"pids":          pids,
					"risk":          "Multiple instances indicate process injection or masquerading",
				},
			})
		}
	}

	return findings
}

func (s *WindowsMemoryScanner) checkSuspiciousPrivileges(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Use whoami to check for dangerous privileges
	output, err := s.ExecCommand(ctx, "whoami", "/priv")
	if err != nil {
		return nil
	}

	dangerousPrivileges := []struct {
		name        string
		description string
		severity    entity.Severity
	}{
		{"SeDebugPrivilege", "Debug programs - allows process injection", entity.SeverityHigh},
		{"SeImpersonatePrivilege", "Impersonate client - token manipulation", entity.SeverityHigh},
		{"SeAssignPrimaryTokenPrivilege", "Replace process token", entity.SeverityHigh},
		{"SeTcbPrivilege", "Act as part of OS - highest privilege", entity.SeverityCritical},
		{"SeLoadDriverPrivilege", "Load kernel drivers", entity.SeverityCritical},
		{"SeRestorePrivilege", "Restore files - can overwrite system files", entity.SeverityHigh},
		{"SeTakeOwnershipPrivilege", "Take ownership of objects", entity.SeverityHigh},
		{"SeBackupPrivilege", "Backup files - can read any file", entity.SeverityMedium},
	}

	for _, priv := range dangerousPrivileges {
		if strings.Contains(output, priv.name) && strings.Contains(output, "Enabled") {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winmem-priv-%s", priv.name),
				Category:    entity.CategoryProcess,
				Severity:    priv.severity,
				Title:       "Dangerous privilege enabled",
				Description: priv.description,
				Path:        "Current Process",
				Details: map[string]interface{}{
					"privilege":   priv.name,
					"description": priv.description,
					"state":       "Enabled",
				},
			})
		}
	}

	return findings
}

func (s *WindowsMemoryScanner) checkLoadedModules(ctx context.Context, processes []windowsProcess) []*entity.Finding {
	var findings []*entity.Finding

	// Check for suspicious DLLs in common injection targets
	for _, target := range []string{"explorer.exe", "svchost.exe"} {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		// Find PID for this target
		var targetPID int
		for _, proc := range processes {
			if strings.EqualFold(proc.Name, target) {
				targetPID = proc.PID
				break
			}
		}

		if targetPID == 0 {
			continue
		}

		// Use tasklist to get DLLs
		output, err := s.ExecCommand(ctx, "tasklist", "/m", "/fi", fmt.Sprintf("PID eq %d", targetPID))
		if err != nil {
			continue
		}

		// Look for suspicious DLLs
		suspiciousDLLPatterns := []string{
			".tmp",
			"temp\\",
			"appdata\\",
			"programdata\\",
		}

		lines := strings.Split(output, "\n")
		for _, line := range lines {
			lineLower := strings.ToLower(line)
			for _, pattern := range suspiciousDLLPatterns {
				if strings.Contains(lineLower, pattern) && strings.Contains(lineLower, ".dll") {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winmem-susdll-%d-%s", targetPID, sanitizeID(line)),
						Category:    entity.CategoryProcess,
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious DLL loaded in system process",
						Description: fmt.Sprintf("Process %s has DLL from suspicious location", target),
						Path:        strings.TrimSpace(line),
						Details: map[string]interface{}{
							"target_process": target,
							"target_pid":     targetPID,
							"dll":            strings.TrimSpace(line),
							"technique":      "T1055 - Process Injection",
						},
					})
					break
				}
			}
		}
	}

	return findings
}

func parseCSVLineForWindows(line string) []string {
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
