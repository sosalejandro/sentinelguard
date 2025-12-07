package scanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// WindowsRegistryScanner detects malicious registry entries and persistence mechanisms
type WindowsRegistryScanner struct {
	BaseScanner
}

// Registry keys commonly abused for persistence
var (
	// Startup/Run keys - comprehensive list per MITRE ATT&CK T1547.001
	startupRegistryKeys = []string{
		// Standard Run keys
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		// 32-bit on 64-bit (WOW6432Node)
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
		// Policy-based Run keys (GPO abuse)
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
		// Explorer load keys
		`HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
	}

	// Winlogon persistence - T1547.004
	winlogonKeys = []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`,
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`,
	}

	// Image File Execution Options (IFEO) - used for debugger hijacking
	ifeoKey = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

	// AppInit DLLs - DLL injection vector
	appInitKeys = []string{
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	}

	// Services registry
	servicesKey = `HKLM\SYSTEM\CurrentControlSet\Services`

	// COM object hijacking locations
	comHijackKeys = []string{
		`HKCU\SOFTWARE\Classes\CLSID`,
		`HKLM\SOFTWARE\Classes\CLSID`,
	}

	// Shell extensions
	shellExtKeys = []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`,
	}

	// Browser Helper Objects
	bhoKey = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

	// Known malicious patterns in registry values - comprehensive detection
	maliciousPatterns = []struct {
		pattern     *regexp.Regexp
		description string
		severity    entity.Severity
	}{
		// PowerShell abuse patterns
		{regexp.MustCompile(`(?i)powershell.*-enc`), "Encoded PowerShell command", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)powershell.*-e\s+[A-Za-z0-9+/=]{20,}`), "Base64 encoded PowerShell", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)powershell.*downloadstring`), "PowerShell download cradle", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)powershell.*invoke-expression`), "PowerShell IEX execution", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*\bIEX\b`), "PowerShell IEX alias", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*-w\s*hidden`), "Hidden PowerShell window", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*bypass`), "PowerShell execution bypass", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)powershell.*invoke-webrequest`), "PowerShell web request", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)powershell.*invoke-restmethod`), "PowerShell REST call", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)powershell.*start-bitstransfer`), "PowerShell BITS transfer", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)powershell.*\[System\.Net\.WebClient\]`), "PowerShell WebClient", entity.SeverityHigh},
		// LOLBin abuse
		{regexp.MustCompile(`(?i)mshta\s+(http|vbscript|javascript)`), "MSHTA script execution", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)wscript.*\.vbs`), "VBScript execution", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)cscript.*\.vbs`), "CScript VBS execution", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)regsvr32.*/s.*/n.*/u.*scrobj`), "Regsvr32 COM scriptlet", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)regsvr32.*/s.*/n.*http`), "Regsvr32 remote scriptlet", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)rundll32.*javascript`), "Rundll32 JavaScript", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)rundll32.*vbscript`), "Rundll32 VBScript", entity.SeverityCritical},
		// Download utilities
		{regexp.MustCompile(`(?i)certutil.*-urlcache`), "Certutil download", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)certutil.*-decode`), "Certutil decode", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)bitsadmin.*/transfer`), "BitsAdmin download", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)curl\.exe.*-o`), "Curl download", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)wget.*-o`), "Wget download", entity.SeverityMedium},
		// Credential dumping indicators
		{regexp.MustCompile(`(?i)comsvcs\.dll.*MiniDump`), "Comsvcs.dll minidump (credential dump)", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)ntdsutil.*ifm`), "NTDS.dit extraction", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)vssadmin.*create.*shadow`), "VSS shadow copy creation", entity.SeverityMedium},
		// Command chaining
		{regexp.MustCompile(`(?i)cmd.*/c.*&.*&`), "Chained command execution", entity.SeverityMedium},
		// Suspicious paths
		{regexp.MustCompile(`(?i)\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\\`), "UNC path to IP address", entity.SeverityHigh},
		{regexp.MustCompile(`(?i)%appdata%.*\\.*\\.*\.exe`), "Suspicious AppData executable", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)%temp%.*\.exe`), "Temp directory executable", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)%public%.*\.exe`), "Public directory executable", entity.SeverityMedium},
		{regexp.MustCompile(`(?i)%localappdata%.*\.exe`), "LocalAppData executable", entity.SeverityMedium},
		// Remote execution
		{regexp.MustCompile(`(?i)wmic.*/node:`), "WMIC remote execution", entity.SeverityCritical},
		{regexp.MustCompile(`(?i)psexec`), "PsExec remote execution", entity.SeverityHigh},
	}

	// Known legitimate BHO CLSIDs to reduce false positives
	legitimateBHOs = map[string]string{
		"{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}": "Adobe PDF Link Helper",
		"{AE7CD045-E861-484f-8273-0445EE161910}": "Adobe PDF Conversion Toolbar Helper",
		"{18DF081C-E8AD-4283-A596-FA578C2EBDC3}": "Adobe PDF Link Helper",
		"{761497BB-D6F0-462C-B6EB-D4DAF1D92D43}": "Java SSV Helper",
		"{DBC80044-A445-435b-BC74-9C25C1C588A9}": "Java Plug-In 2 SSV Helper",
		"{95B7759C-8C7F-4BF1-B163-73684A933233}": "AVG SafeGuard toolbar",
		"{BF42D4A8-016E-4fcd-B1EB-837659FD77C6}": "Norton Identity Protection",
		"{602ADB0E-4AFF-4217-8AA1-95DAC4DFA408}": "Norton Toolbar",
		"{27B4851A-3207-45A2-B947-BE8AFE6163AB}": "Norton Toolbar",
	}

	// Known legitimate HKCU CLSIDs to reduce COM hijacking false positives
	// These are commonly registered by legitimate applications
	legitimateCOMCLSIDs = map[string]string{
		// Microsoft Office
		"{000209FF-0000-0000-C000-000000000046}": "Microsoft Word Application",
		"{00024500-0000-0000-C000-000000000046}": "Microsoft Excel Application",
		"{91493441-5A91-11CF-8700-00AA0060263B}": "Microsoft PowerPoint Application",
		"{0006F03A-0000-0000-C000-000000000046}": "Microsoft Outlook Application",
		// Windows Shell Extensions
		"{86CA1AA0-34AA-4E8B-A509-50C905BAE2A2}": "Windows 11 Context Menu",
		"{1D2680C9-0E2A-469D-B787-065558BC7D43}": "Fusion Cache",
		"{018D5C66-4533-4307-9B53-224DE2ED1FE6}": "OneDrive Shell Extension",
		"{CB3D0F55-BC2C-4C1A-85ED-23ED75B5106B}": "Windows Search Protocol Host",
		// Common application frameworks
		"{D5CDD505-2E9C-101B-9397-08002B2CF9AE}": "Property Page Shell Extension",
		"{3D1975AF-48C6-4F8E-A182-BE0E08FA86A9}": ".NET Framework",
		"{F5078F32-C551-11D3-89B9-0000F81FE221}": "MSXML DOM Document 3.0",
		"{2933BF90-7B36-11D2-B20E-00C04F983E60}": "MSXML DOM Document",
		// Visual Studio
		"{B4F97281-0DBD-4835-9ED8-7DFB966E87FF}": "Visual Studio Code Context Handler",
		// Adobe
		"{B801CA65-A1FC-11D0-85AD-444553540000}": "Adobe PDF IFilter",
		// Google
		"{A2DF06F9-A21A-44A8-8A99-8B9C84F29160}": "Google Chrome",
		// Nvidia
		"{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}": "NVIDIA Display Container LS",
	}

	// Legitimate paths for COM servers (not suspicious even in HKCU)
	legitimateCOMPaths = []string{
		`\microsoft\`,
		`\windows\system32\`,
		`\windows\syswow64\`,
		`\program files\`,
		`\program files (x86)\`,
		`\common files\`,
	}

	// Suspicious Winlogon values
	suspiciousWinlogonValues = []string{
		"Shell",
		"Userinit",
		"Taskman",
		"AppSetup",
	}

	// Legitimate Winlogon defaults
	legitimateWinlogonDefaults = map[string]string{
		"Shell":    "explorer.exe",
		"Userinit": "C:\\Windows\\system32\\userinit.exe,",
	}
)

func NewWindowsRegistryScanner() *WindowsRegistryScanner {
	return &WindowsRegistryScanner{
		BaseScanner: NewBaseScanner("windows-registry", "Windows registry persistence and malware detector"),
	}
}

func (s *WindowsRegistryScanner) Category() entity.FindingCategory {
	return entity.CategoryPersistence
}

func (s *WindowsRegistryScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting Windows registry scan")
	var findings []*entity.Finding

	// Check startup/Run keys
	if f := s.checkStartupKeys(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check Winlogon persistence
	if f := s.checkWinlogonKeys(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check Image File Execution Options (debugger hijacking)
	if f := s.checkIFEO(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check AppInit DLLs
	if f := s.checkAppInitDLLs(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for suspicious services
	if f := s.checkSuspiciousServices(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check COM hijacking
	if f := s.checkCOMHijacking(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check Browser Helper Objects
	if f := s.checkBHO(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for known malware registry indicators
	if f := s.checkKnownMalwareIndicators(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check scheduled tasks for malicious content
	if f := s.checkScheduledTasks(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("Windows registry scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *WindowsRegistryScanner) checkStartupKeys(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	for _, key := range startupRegistryKeys {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := s.queryRegistryKey(ctx, key)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// Check for malicious patterns
			for _, pattern := range maliciousPatterns {
				if pattern.pattern.MatchString(entry.Value) {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winreg-startup-malicious-%s-%s", sanitizeID(key), sanitizeID(entry.Name)),
						Category:    entity.CategoryPersistence,
						Severity:    pattern.severity,
						Title:       "Malicious registry startup entry",
						Description: fmt.Sprintf("Registry value contains %s", pattern.description),
						Path:        key,
						Details: map[string]interface{}{
							"key":         key,
							"value_name":  entry.Name,
							"value_data":  entry.Value,
							"pattern":     pattern.description,
							"value_type":  entry.Type,
						},
					})
					break
				}
			}

			// Check for suspicious paths (non-standard locations)
			if s.isSuspiciousPath(entry.Value) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winreg-startup-suspath-%s-%s", sanitizeID(key), sanitizeID(entry.Name)),
					Category:    entity.CategoryPersistence,
					Severity:    entity.SeverityMedium,
					Title:       "Suspicious startup entry path",
					Description: "Startup entry points to non-standard location",
					Path:        key,
					Details: map[string]interface{}{
						"key":        key,
						"value_name": entry.Name,
						"value_data": entry.Value,
						"value_type": entry.Type,
					},
				})
			}
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkWinlogonKeys(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	for _, key := range winlogonKeys {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := s.queryRegistryKey(ctx, key)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// Check suspicious Winlogon values
			for _, susValue := range suspiciousWinlogonValues {
				if strings.EqualFold(entry.Name, susValue) {
					// Check if it's the default legitimate value
					if defaultVal, ok := legitimateWinlogonDefaults[susValue]; ok {
						if strings.EqualFold(strings.TrimSpace(entry.Value), strings.TrimSpace(defaultVal)) {
							continue
						}
					}

					// Non-default value - suspicious
					severity := entity.SeverityHigh
					if strings.EqualFold(susValue, "Shell") || strings.EqualFold(susValue, "Userinit") {
						severity = entity.SeverityCritical
					}

					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winreg-winlogon-%s", sanitizeID(entry.Name)),
						Category:    entity.CategoryPersistence,
						Severity:    severity,
						Title:       "Modified Winlogon registry value",
						Description: fmt.Sprintf("Winlogon %s has non-default value", entry.Name),
						Path:        key,
						Details: map[string]interface{}{
							"key":           key,
							"value_name":    entry.Name,
							"value_data":    entry.Value,
							"expected":      legitimateWinlogonDefaults[susValue],
							"risk":          "May execute malicious code at login",
						},
					})
				}
			}
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkIFEO(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Query IFEO for subkeys
	output, err := s.ExecCommand(ctx, "reg", "query", ifeoKey)
	if err != nil {
		return nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HKEY_") {
			continue
		}

		// Query each subkey for Debugger value
		entries, err := s.queryRegistryKey(ctx, line)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if strings.EqualFold(entry.Name, "Debugger") && entry.Value != "" {
				// Extract the target executable name from the key path
				parts := strings.Split(line, "\\")
				targetExe := parts[len(parts)-1]

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winreg-ifeo-%s", sanitizeID(targetExe)),
					Category:    entity.CategoryPersistence,
					Severity:    entity.SeverityCritical,
					Title:       "Image File Execution Options debugger set",
					Description: fmt.Sprintf("IFEO debugger hijack for %s", targetExe),
					Path:        line,
					Details: map[string]interface{}{
						"target_executable": targetExe,
						"debugger_value":    entry.Value,
						"technique":         "T1546.012 - Image File Execution Options Injection",
						"risk":              "Malware can intercept program execution",
					},
				})
			}

			// Check for GlobalFlag (silent process exit monitoring)
			if strings.EqualFold(entry.Name, "GlobalFlag") {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winreg-ifeo-globalflag-%s", sanitizeID(line)),
					Category:    entity.CategoryPersistence,
					Severity:    entity.SeverityHigh,
					Title:       "IFEO GlobalFlag set",
					Description: "GlobalFlag registry value set - may indicate silent process exit abuse",
					Path:        line,
					Details: map[string]interface{}{
						"key":        line,
						"value_name": entry.Name,
						"value_data": entry.Value,
					},
				})
			}
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkAppInitDLLs(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	for _, key := range appInitKeys {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := s.queryRegistryKey(ctx, key)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if strings.EqualFold(entry.Name, "AppInit_DLLs") && entry.Value != "" {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winreg-appinit-%s", sanitizeID(key)),
					Category:    entity.CategoryPersistence,
					Severity:    entity.SeverityCritical,
					Title:       "AppInit_DLLs configured",
					Description: "AppInit_DLLs injects DLL into all user-mode processes",
					Path:        key,
					Details: map[string]interface{}{
						"key":       key,
						"dll_path":  entry.Value,
						"technique": "T1546.010 - AppInit DLLs",
						"risk":      "DLL loaded into all processes using User32.dll",
					},
				})
			}

			if strings.EqualFold(entry.Name, "LoadAppInit_DLLs") {
				if entry.Value == "1" || entry.Value == "0x1" {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winreg-appinit-enabled-%s", sanitizeID(key)),
						Category:    entity.CategoryPersistence,
						Severity:    entity.SeverityHigh,
						Title:       "AppInit_DLLs loading enabled",
						Description: "LoadAppInit_DLLs is enabled",
						Path:        key,
						Details: map[string]interface{}{
							"key":   key,
							"value": entry.Value,
						},
					})
				}
			}
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkSuspiciousServices(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Get list of service subkeys
	output, err := s.ExecCommand(ctx, "reg", "query", servicesKey)
	if err != nil {
		return nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HKEY_") {
			continue
		}

		entries, err := s.queryRegistryKey(ctx, line)
		if err != nil {
			continue
		}

		var imagePath, displayName, serviceName string
		for _, entry := range entries {
			switch strings.ToLower(entry.Name) {
			case "imagepath":
				imagePath = entry.Value
			case "displayname":
				displayName = entry.Value
			}
		}

		// Extract service name from key
		parts := strings.Split(line, "\\")
		if len(parts) > 0 {
			serviceName = parts[len(parts)-1]
		}

		if imagePath == "" {
			continue
		}

		// Check for suspicious service image paths
		for _, pattern := range maliciousPatterns {
			if pattern.pattern.MatchString(imagePath) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winreg-service-malicious-%s", sanitizeID(serviceName)),
					Category:    entity.CategoryPersistence,
					Severity:    pattern.severity,
					Title:       "Suspicious service image path",
					Description: fmt.Sprintf("Service %s has suspicious image path", serviceName),
					Path:        line,
					Details: map[string]interface{}{
						"service_name": serviceName,
						"display_name": displayName,
						"image_path":   imagePath,
						"pattern":      pattern.description,
					},
				})
				break
			}
		}

		// Check for suspicious paths
		if s.isSuspiciousPath(imagePath) {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winreg-service-suspath-%s", sanitizeID(serviceName)),
				Category:    entity.CategoryPersistence,
				Severity:    entity.SeverityMedium,
				Title:       "Service running from suspicious path",
				Description: fmt.Sprintf("Service %s runs from non-standard location", serviceName),
				Path:        line,
				Details: map[string]interface{}{
					"service_name": serviceName,
					"display_name": displayName,
					"image_path":   imagePath,
				},
			})
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkCOMHijacking(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Focus on HKCU CLSID which can override HKLM (COM hijacking)
	hkcuCLSID := `HKCU\SOFTWARE\Classes\CLSID`

	output, err := s.ExecCommand(ctx, "reg", "query", hkcuCLSID, "/s")
	if err != nil {
		return nil
	}

	// Look for InprocServer32 or LocalServer32 entries
	lines := strings.Split(output, "\n")
	var currentKey string
	var currentCLSID string
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "HKEY_") {
			currentKey = line
			// Extract CLSID from the key path
			parts := strings.Split(currentKey, "\\")
			for _, part := range parts {
				if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
					currentCLSID = part
					break
				}
			}
			continue
		}

		// Check for server entries
		if strings.Contains(strings.ToLower(line), "inprocserver32") ||
			strings.Contains(strings.ToLower(line), "localserver32") {

			fields := strings.Fields(line)
			if len(fields) >= 3 {
				serverPath := strings.Join(fields[2:], " ")
				serverPathLower := strings.ToLower(serverPath)

				// Skip if this is a known legitimate CLSID
				if _, isLegitimate := legitimateCOMCLSIDs[currentCLSID]; isLegitimate {
					s.log.Debug("skipping known legitimate COM CLSID",
						zap.String("clsid", currentCLSID),
						zap.String("path", serverPath))
					continue
				}

				// Skip if the server path is in a legitimate location
				isLegitPath := false
				for _, legitPath := range legitimateCOMPaths {
					if strings.Contains(serverPathLower, legitPath) {
						isLegitPath = true
						break
					}
				}
				if isLegitPath {
					s.log.Debug("skipping COM registration with legitimate path",
						zap.String("clsid", currentCLSID),
						zap.String("path", serverPath))
					continue
				}

				// Determine severity based on server path
				severity := entity.SeverityMedium
				if s.isSuspiciousPath(serverPath) {
					severity = entity.SeverityCritical
				} else {
					// User-level COM in non-standard location is still suspicious
					severity = entity.SeverityHigh
				}

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winreg-comhijack-%s", sanitizeID(currentCLSID)),
					Category:    entity.CategoryPersistence,
					Severity:    severity,
					Title:       "Potential COM object hijacking",
					Description: "User-level CLSID registration can override system COM objects",
					Path:        currentKey,
					Details: map[string]interface{}{
						"clsid":       currentCLSID,
						"server_path": serverPath,
						"technique":   "T1546.015 - COM Hijacking",
						"note":        "Not in known legitimate CLSID list",
					},
				})
			}
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkBHO(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	output, err := s.ExecCommand(ctx, "reg", "query", bhoKey)
	if err != nil {
		return nil
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "HKEY_") {
			continue
		}

		// Extract CLSID from the key path
		parts := strings.Split(line, "\\")
		if len(parts) > 0 {
			clsid := parts[len(parts)-1]

			// Check if this is a known legitimate BHO
			if legitName, isLegit := legitimateBHOs[clsid]; isLegit {
				s.log.Debug("skipping known legitimate BHO",
					zap.String("clsid", clsid),
					zap.String("name", legitName))
				continue
			}

			// Look up the CLSID to find the DLL path
			clsidKey := fmt.Sprintf(`HKLM\SOFTWARE\Classes\CLSID\%s\InprocServer32`, clsid)
			entries, _ := s.queryRegistryKey(ctx, clsidKey)

			var dllPath string
			for _, entry := range entries {
				if entry.Name == "(Default)" || entry.Name == "" {
					dllPath = entry.Value
					break
				}
			}

			// Determine severity based on DLL path
			severity := entity.SeverityMedium
			if s.isSuspiciousPath(dllPath) {
				severity = entity.SeverityHigh
			}

			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winreg-bho-%s", sanitizeID(clsid)),
				Category:    entity.CategoryPersistence,
				Severity:    severity,
				Title:       "Unknown Browser Helper Object registered",
				Description: "BHO can inject code into Internet Explorer",
				Path:        line,
				Details: map[string]interface{}{
					"clsid":    clsid,
					"dll_path": dllPath,
					"risk":     "BHOs can monitor browser activity and inject content",
					"note":     "Not in known legitimate BHO list",
				},
			})
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkKnownMalwareIndicators(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Known malware registry locations
	malwareIndicators := []struct {
		key         string
		description string
		severity    entity.Severity
	}{
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers`, "Shell icon overlay (can be abused for persistence)", entity.SeverityLow},
		{`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts`, "File extension handlers (can redirect execution)", entity.SeverityLow},
		{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers`, "Credential provider (can capture passwords)", entity.SeverityHigh},
		{`HKLM\SOFTWARE\Microsoft\Netsh`, "Netsh helper DLL (network interception)", entity.SeverityHigh},
		{`HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors`, "Print monitor (runs as SYSTEM)", entity.SeverityHigh},
		{`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages`, "Security package (credential access)", entity.SeverityCritical},
		{`HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages`, "Authentication package (credential access)", entity.SeverityCritical},
	}

	for _, indicator := range malwareIndicators {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		entries, err := s.queryRegistryKey(ctx, indicator.key)
		if err != nil {
			continue
		}

		// For high-risk keys, report any non-default entries
		if indicator.severity >= entity.SeverityHigh && len(entries) > 0 {
			for _, entry := range entries {
				if s.isSuspiciousPath(entry.Value) {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winreg-indicator-%s-%s", sanitizeID(indicator.key), sanitizeID(entry.Name)),
						Category:    entity.CategoryPersistence,
						Severity:    indicator.severity,
						Title:       "Suspicious registry indicator",
						Description: indicator.description,
						Path:        indicator.key,
						Details: map[string]interface{}{
							"key":        indicator.key,
							"value_name": entry.Name,
							"value_data": entry.Value,
						},
					})
				}
			}
		}
	}

	return findings
}

func (s *WindowsRegistryScanner) checkScheduledTasks(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Get scheduled tasks using schtasks with verbose output
	output, err := s.ExecCommand(ctx, "schtasks", "/query", "/fo", "csv", "/v")
	if err != nil {
		s.log.Debug("failed to query scheduled tasks", zap.Error(err))
		return nil
	}

	lines := strings.Split(output, "\n")
	var headerMap map[string]int

	for i, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := s.parseScheduledTaskCSVLine(line)

		// Parse header line
		if i == 0 || headerMap == nil {
			headerMap = make(map[string]int)
			for j, field := range fields {
				cleanField := strings.Trim(field, "\"")
				headerMap[cleanField] = j
			}
			continue
		}

		// Extract task information
		var taskName, taskAction, taskState string

		if idx, ok := headerMap["TaskName"]; ok && idx < len(fields) {
			taskName = strings.Trim(fields[idx], "\"")
		}
		if idx, ok := headerMap["Task To Run"]; ok && idx < len(fields) {
			taskAction = strings.Trim(fields[idx], "\"")
		}
		if idx, ok := headerMap["Status"]; ok && idx < len(fields) {
			taskState = strings.Trim(fields[idx], "\"")
		}

		// Skip system tasks (Microsoft Windows tasks)
		if strings.HasPrefix(taskName, "\\Microsoft\\Windows\\") {
			continue
		}

		// Skip empty actions
		if taskAction == "" || taskAction == "N/A" {
			continue
		}

		// Check task action for malicious patterns
		for _, pattern := range maliciousPatterns {
			if pattern.pattern.MatchString(taskAction) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winreg-schtask-malicious-%s", sanitizeID(taskName)),
					Category:    entity.CategoryPersistence,
					Severity:    pattern.severity,
					Title:       "Suspicious scheduled task detected",
					Description: fmt.Sprintf("Scheduled task contains %s", pattern.description),
					Path:        taskName,
					Details: map[string]interface{}{
						"task_name":   taskName,
						"task_action": taskAction,
						"task_state":  taskState,
						"pattern":     pattern.description,
						"technique":   "T1053.005 - Scheduled Task/Job: Scheduled Task",
					},
				})
				break
			}
		}

		// Check for suspicious paths in task actions
		if s.isSuspiciousPath(taskAction) {
			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winreg-schtask-suspath-%s", sanitizeID(taskName)),
				Category:    entity.CategoryPersistence,
				Severity:    entity.SeverityMedium,
				Title:       "Scheduled task with suspicious path",
				Description: "Task executes from non-standard location",
				Path:        taskName,
				Details: map[string]interface{}{
					"task_name":   taskName,
					"task_action": taskAction,
					"task_state":  taskState,
				},
			})
		}

		// Check for tasks created by non-Microsoft sources with admin execution
		if !strings.HasPrefix(taskName, "\\Microsoft\\") && taskState == "Ready" {
			// Check if it runs as SYSTEM or admin
			var runAsUser string
			if idx, ok := headerMap["Run As User"]; ok && idx < len(fields) {
				runAsUser = strings.ToLower(strings.Trim(fields[idx], "\""))
			}
			if strings.Contains(runAsUser, "system") || strings.Contains(runAsUser, "administrator") {
				// Check for additional suspicious indicators
				actionLower := strings.ToLower(taskAction)
				if strings.Contains(actionLower, "powershell") ||
					strings.Contains(actionLower, "cmd") ||
					strings.Contains(actionLower, "wscript") ||
					strings.Contains(actionLower, "cscript") ||
					strings.Contains(actionLower, "mshta") {

					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winreg-schtask-adminscript-%s", sanitizeID(taskName)),
						Category:    entity.CategoryPersistence,
						Severity:    entity.SeverityHigh,
						Title:       "Privileged script execution via scheduled task",
						Description: fmt.Sprintf("Task runs scripts as %s", runAsUser),
						Path:        taskName,
						Details: map[string]interface{}{
							"task_name":   taskName,
							"task_action": taskAction,
							"run_as_user": runAsUser,
							"risk":        "High-privilege script execution can be used for persistence",
						},
					})
				}
			}
		}
	}

	return findings
}

// parseScheduledTaskCSVLine handles CSV parsing with proper quote handling
func (s *WindowsRegistryScanner) parseScheduledTaskCSVLine(line string) []string {
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

// Helper functions

type registryEntry struct {
	Name  string
	Type  string
	Value string
}

func (s *WindowsRegistryScanner) queryRegistryKey(ctx context.Context, key string) ([]registryEntry, error) {
	var entries []registryEntry

	output, err := s.ExecCommand(ctx, "reg", "query", key)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "HKEY_") {
			continue
		}

		// Parse: Name    REG_TYPE    Value
		// Handle the case where value might contain spaces
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			entry := registryEntry{
				Name:  fields[0],
				Type:  fields[1],
				Value: strings.Join(fields[2:], " "),
			}
			entries = append(entries, entry)
		} else if len(fields) == 2 {
			// Value might be empty
			entry := registryEntry{
				Name:  fields[0],
				Type:  fields[1],
				Value: "",
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func (s *WindowsRegistryScanner) isSuspiciousPath(path string) bool {
	pathLower := strings.ToLower(path)

	// Suspicious path patterns
	suspiciousPaths := []string{
		`%temp%`,
		`%appdata%`,
		`%localappdata%`,
		`%public%`,
		`\users\public\`,
		`\programdata\`,
		`\recycler\`,
		`\$recycle.bin\`,
		`\perflogs\`,
		`\windows\temp\`,
		`\windows\debug\`,
	}

	for _, sus := range suspiciousPaths {
		if strings.Contains(pathLower, sus) {
			return true
		}
	}

	// Check for executables in user-writable locations without full path
	if strings.HasSuffix(pathLower, ".exe") || strings.HasSuffix(pathLower, ".dll") {
		// No path separator = just filename, could run from PATH hijacking
		if !strings.Contains(path, "\\") && !strings.Contains(path, "/") {
			return true
		}
	}

	return false
}

func sanitizeID(s string) string {
	// Replace characters that shouldn't be in IDs
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, ":", "")
	if len(s) > 50 {
		s = s[:50]
	}
	return s
}
