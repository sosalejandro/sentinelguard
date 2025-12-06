package scanner

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// WindowsKernelScanner detects suspicious drivers, kernel-level rootkits, and system integrity issues
type WindowsKernelScanner struct {
	BaseScanner
}

// Known rootkit drivers and suspicious patterns
var (
	// Known malicious/rootkit driver names
	knownMaliciousDrivers = map[string]string{
		"win32k.sys":       "", // Legitimate but often targeted - skip
		"tmlisten":         "Possible TDL rootkit component",
		"tdss":             "TDSS/TDL rootkit",
		"tdl":              "TDL rootkit",
		"maxplus":          "MaxPlus rootkit",
		"atrsd":            "Atrax rootkit",
		"rkhdrv":           "Generic rootkit driver",
		"mracdrv":          "Mebroot/Sinowal rootkit",
		"gxvss":            "Suspicious gaming cheat/rootkit",
		"beep_":            "Possible rootkit hiding as beep driver",
		"volmgr_":          "Possible rootkit masquerading as volmgr",
		"fltmgr_":          "Possible rootkit masquerading as fltmgr",
	}

	// Suspicious driver path patterns
	suspiciousDriverPaths = []string{
		`\temp\`,
		`\tmp\`,
		`\users\`,
		`\appdata\`,
		`\programdata\`,
		`\downloads\`,
		`\desktop\`,
		`\documents\`,
	}

	// Driver names that should only exist in System32\drivers
	systemDrivers = []string{
		"ntfs.sys",
		"tcpip.sys",
		"http.sys",
		"srv.sys",
		"ndis.sys",
		"nsiproxy.sys",
		"afd.sys",
		"netbt.sys",
		"fltmgr.sys",
		"ksecdd.sys",
		"cng.sys",
		"pcw.sys",
		"msrpc.sys",
	}

	// Filter driver altitude patterns (minifilters)
	suspiciousAltitudes = []struct {
		min         int
		max         int
		description string
		severity    entity.Severity
	}{
		{320000, 329999, "Encryption filter (ransomware risk)", entity.SeverityHigh},
		{140000, 149999, "General activity monitor", entity.SeverityMedium},
		{100000, 109999, "Top of filter stack (intercept all)", entity.SeverityHigh},
		{40000, 49999, "Bottom of stack (last access)", entity.SeverityMedium},
	}
)

func NewWindowsKernelScanner() *WindowsKernelScanner {
	return &WindowsKernelScanner{
		BaseScanner: NewBaseScanner("windows-kernel", "Windows driver and kernel rootkit detector"),
	}
}

func (s *WindowsKernelScanner) Category() entity.FindingCategory {
	return entity.CategoryRootkit
}

func (s *WindowsKernelScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting Windows kernel and driver scan")
	var findings []*entity.Finding

	// Enumerate all loaded drivers
	if f := s.checkLoadedDrivers(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check driver signatures
	if f := s.checkDriverSignatures(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check minifilter drivers
	if f := s.checkMinifilterDrivers(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for hidden drivers (registry vs loaded)
	if f := s.checkHiddenDrivers(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check kernel integrity settings
	if f := s.checkKernelIntegrity(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for suspicious callbacks
	if f := s.checkDriverCallbacks(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check WMI persistence
	if f := s.checkWMIPersistence(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("Windows kernel scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

type windowsDriver struct {
	Name       string
	Path       string
	State      string
	StartType  string
	Type       string
	Signed     bool
	SignerName string
}

func (s *WindowsKernelScanner) checkLoadedDrivers(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Use driverquery for loaded drivers
	output, err := s.ExecCommand(ctx, "driverquery", "/v", "/fo", "csv")
	if err != nil {
		s.log.Debug("driverquery failed", zap.Error(err))
		return nil
	}

	lines := strings.Split(output, "\n")
	headerParsed := false

	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := parseCSVLineForWindows(line)

		if !headerParsed {
			headerParsed = true
			continue
		}

		if len(fields) < 5 {
			continue
		}

		driver := windowsDriver{
			Name:  strings.Trim(fields[0], "\""),
			State: strings.Trim(fields[3], "\""),
		}

		// Get path from registry if not in driverquery
		if len(fields) > 8 {
			driver.Path = strings.Trim(fields[8], "\"")
		}

		// Check for known malicious drivers
		driverNameLower := strings.ToLower(driver.Name)
		for pattern, description := range knownMaliciousDrivers {
			if description == "" {
				continue // Skip empty descriptions (legitimate drivers)
			}
			if strings.Contains(driverNameLower, pattern) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winkernel-malicious-%s", sanitizeID(driver.Name)),
					Category:    entity.CategoryRootkit,
					Severity:    entity.SeverityCritical,
					Title:       "Known malicious driver detected",
					Description: description,
					Path:        driver.Path,
					Details: map[string]interface{}{
						"driver_name": driver.Name,
						"driver_path": driver.Path,
						"state":       driver.State,
						"pattern":     pattern,
					},
				})
			}
		}

		// Check for drivers in suspicious locations
		if driver.Path != "" {
			pathLower := strings.ToLower(driver.Path)
			for _, susPath := range suspiciousDriverPaths {
				if strings.Contains(pathLower, susPath) {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winkernel-suspath-%s", sanitizeID(driver.Name)),
						Category:    entity.CategoryRootkit,
						Severity:    entity.SeverityHigh,
						Title:       "Driver loaded from suspicious location",
						Description: fmt.Sprintf("Driver %s loaded from %s", driver.Name, susPath),
						Path:        driver.Path,
						Details: map[string]interface{}{
							"driver_name":    driver.Name,
							"driver_path":    driver.Path,
							"suspicious_dir": susPath,
						},
					})
					break
				}
			}

			// Check if system driver is in wrong location
			for _, sysDriver := range systemDrivers {
				if strings.EqualFold(driver.Name+".sys", sysDriver) ||
					strings.EqualFold(filepath.Base(driver.Path), sysDriver) {
					if !strings.Contains(pathLower, `\system32\drivers\`) &&
						!strings.Contains(pathLower, `\syswow64\`) {
						findings = append(findings, &entity.Finding{
							ID:          fmt.Sprintf("winkernel-wrongloc-%s", sanitizeID(driver.Name)),
							Category:    entity.CategoryRootkit,
							Severity:    entity.SeverityCritical,
							Title:       "System driver in wrong location",
							Description: fmt.Sprintf("System driver %s running from non-standard path", driver.Name),
							Path:        driver.Path,
							Details: map[string]interface{}{
								"driver_name":   driver.Name,
								"actual_path":   driver.Path,
								"expected_path": `C:\Windows\System32\drivers\`,
							},
						})
					}
				}
			}
		}
	}

	return findings
}

func (s *WindowsKernelScanner) checkDriverSignatures(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check driver signing enforcement
	output, err := s.ExecCommand(ctx, "bcdedit", "/enum")
	if err != nil {
		s.log.Debug("bcdedit failed", zap.Error(err))
		return nil
	}

	// Check for testsigning or nointegritychecks
	outputLower := strings.ToLower(output)

	if strings.Contains(outputLower, "testsigning") && strings.Contains(outputLower, "yes") {
		findings = append(findings, &entity.Finding{
			ID:          "winkernel-testsigning",
			Category:    entity.CategoryRootkit,
			Severity:    entity.SeverityCritical,
			Title:       "Test signing mode enabled",
			Description: "Windows is in test signing mode, allowing unsigned drivers",
			Path:        "bcdedit",
			Details: map[string]interface{}{
				"setting": "testsigning",
				"value":   "Yes",
				"risk":    "Unsigned malicious drivers can be loaded",
			},
		})
	}

	if strings.Contains(outputLower, "nointegritychecks") && strings.Contains(outputLower, "yes") {
		findings = append(findings, &entity.Finding{
			ID:          "winkernel-nointegrity",
			Category:    entity.CategoryRootkit,
			Severity:    entity.SeverityCritical,
			Title:       "Driver integrity checks disabled",
			Description: "Windows driver integrity checks are disabled",
			Path:        "bcdedit",
			Details: map[string]interface{}{
				"setting": "nointegritychecks",
				"value":   "Yes",
				"risk":    "Driver signatures are not verified",
			},
		})
	}

	// Check for debug mode
	if strings.Contains(outputLower, "debug") && strings.Contains(outputLower, "yes") {
		findings = append(findings, &entity.Finding{
			ID:          "winkernel-debug",
			Category:    entity.CategoryRootkit,
			Severity:    entity.SeverityHigh,
			Title:       "Kernel debug mode enabled",
			Description: "Windows kernel debugging is enabled",
			Path:        "bcdedit",
			Details: map[string]interface{}{
				"setting": "debug",
				"value":   "Yes",
				"risk":    "Kernel debugging allows memory inspection/modification",
			},
		})
	}

	return findings
}

func (s *WindowsKernelScanner) checkMinifilterDrivers(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Query minifilter drivers using fltmc
	output, err := s.ExecCommand(ctx, "fltmc", "filters")
	if err != nil {
		s.log.Debug("fltmc failed", zap.Error(err))
		return nil
	}

	// Parse fltmc output
	// Format: Filter Name                     Num Instances    Altitude    Frame
	lines := strings.Split(output, "\n")
	headerPassed := false

	for _, line := range lines {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "---") {
			headerPassed = true
			continue
		}

		if !headerPassed {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		filterName := fields[0]
		altitudeStr := ""
		if len(fields) >= 3 {
			altitudeStr = fields[2]
		}

		// Check filter name for suspicious patterns
		filterNameLower := strings.ToLower(filterName)
		for pattern, description := range knownMaliciousDrivers {
			if description == "" {
				continue
			}
			if strings.Contains(filterNameLower, pattern) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winkernel-filter-malicious-%s", sanitizeID(filterName)),
					Category:    entity.CategoryRootkit,
					Severity:    entity.SeverityCritical,
					Title:       "Suspicious minifilter driver",
					Description: description,
					Path:        filterName,
					Details: map[string]interface{}{
						"filter_name": filterName,
						"altitude":    altitudeStr,
						"pattern":     pattern,
					},
				})
			}
		}

		// Check altitude for suspicious ranges
		// Extract numeric altitude
		altitudeRegex := regexp.MustCompile(`(\d+)`)
		matches := altitudeRegex.FindStringSubmatch(altitudeStr)
		if len(matches) >= 2 {
			var altitude int
			fmt.Sscanf(matches[1], "%d", &altitude)

			for _, altRange := range suspiciousAltitudes {
				if altitude >= altRange.min && altitude <= altRange.max {
					// Check if it's a known legitimate filter at this altitude
					knownFilters := []string{"avgflt", "epfwwfpr", "mbamswissarmy", "wdfilter"}
					isKnown := false
					for _, known := range knownFilters {
						if strings.Contains(filterNameLower, known) {
							isKnown = true
							break
						}
					}

					if !isKnown {
						findings = append(findings, &entity.Finding{
							ID:          fmt.Sprintf("winkernel-filter-altitude-%s", sanitizeID(filterName)),
							Category:    entity.CategoryRootkit,
							Severity:    altRange.severity,
							Title:       "Minifilter at suspicious altitude",
							Description: fmt.Sprintf("%s - %s", filterName, altRange.description),
							Path:        filterName,
							Details: map[string]interface{}{
								"filter_name": filterName,
								"altitude":    altitude,
								"range":       fmt.Sprintf("%d-%d", altRange.min, altRange.max),
								"description": altRange.description,
							},
						})
					}
				}
			}
		}
	}

	return findings
}

func (s *WindowsKernelScanner) checkHiddenDrivers(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Get drivers from registry
	registryDrivers := make(map[string]bool)
	output, err := s.ExecCommand(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Services`, "/s", "/f", "Type", "/d")
	if err == nil {
		lines := strings.Split(output, "\n")
		currentService := ""
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "HKEY_LOCAL_MACHINE") {
				// Extract service name
				parts := strings.Split(line, "\\")
				if len(parts) > 0 {
					currentService = parts[len(parts)-1]
				}
			}
			// Type 1 = Kernel driver, Type 2 = File system driver
			if strings.Contains(line, "REG_DWORD") &&
				(strings.Contains(line, "0x1") || strings.Contains(line, "0x2")) {
				registryDrivers[strings.ToLower(currentService)] = true
			}
		}
	}

	// Get loaded drivers from system
	loadedDrivers := make(map[string]bool)
	output, err = s.ExecCommand(ctx, "driverquery", "/fo", "csv")
	if err == nil {
		lines := strings.Split(output, "\n")
		for _, line := range lines[1:] {
			fields := parseCSVLineForWindows(line)
			if len(fields) >= 1 {
				driverName := strings.Trim(fields[0], "\"")
				loadedDrivers[strings.ToLower(driverName)] = true
			}
		}
	}

	// Check for registry drivers not loaded (could be disabled malware)
	for regDriver := range registryDrivers {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !loadedDrivers[regDriver] {
			// Query more details about this service
			servicePath := fmt.Sprintf(`HKLM\SYSTEM\CurrentControlSet\Services\%s`, regDriver)
			details, _ := s.ExecCommand(ctx, "reg", "query", servicePath)

			// Check if it's set to start automatically but isn't running
			if strings.Contains(strings.ToLower(details), "start") &&
				(strings.Contains(details, "0x0") || strings.Contains(details, "0x1") || strings.Contains(details, "0x2")) {

				// Check ImagePath for suspicious locations
				isSuspicious := false
				for _, susPath := range suspiciousDriverPaths {
					if strings.Contains(strings.ToLower(details), susPath) {
						isSuspicious = true
						break
					}
				}

				if isSuspicious {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("winkernel-hidden-%s", sanitizeID(regDriver)),
						Category:    entity.CategoryRootkit,
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious driver in registry but not loaded",
						Description: fmt.Sprintf("Driver %s registered but not running", regDriver),
						Path:        servicePath,
						Details: map[string]interface{}{
							"driver_name":  regDriver,
							"registry_key": servicePath,
							"details":      details,
							"risk":         "May be dormant malware or failed rootkit",
						},
					})
				}
			}
		}
	}

	return findings
}

func (s *WindowsKernelScanner) checkKernelIntegrity(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check Secure Boot status
	output, err := s.ExecCommand(ctx, "powershell", "-Command",
		"Confirm-SecureBootUEFI 2>$null; if($?) { 'Enabled' } else { 'Disabled' }")
	if err == nil {
		if strings.Contains(strings.ToLower(output), "disabled") ||
			strings.Contains(strings.ToLower(output), "false") {
			findings = append(findings, &entity.Finding{
				ID:          "winkernel-secureboot-disabled",
				Category:    entity.CategoryRootkit,
				Severity:    entity.SeverityMedium,
				Title:       "Secure Boot not enabled",
				Description: "Secure Boot is disabled, allowing unsigned bootloaders",
				Path:        "UEFI",
				Details: map[string]interface{}{
					"status": "Disabled",
					"risk":   "Boot-level malware can load before OS",
				},
			})
		}
	}

	// Check HVCI (Hypervisor-protected Code Integrity)
	output, err = s.ExecCommand(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`,
		"/v", "Enabled")
	if err == nil {
		if !strings.Contains(output, "0x1") {
			findings = append(findings, &entity.Finding{
				ID:          "winkernel-hvci-disabled",
				Category:    entity.CategoryRootkit,
				Severity:    entity.SeverityLow,
				Title:       "HVCI not enabled",
				Description: "Hypervisor-protected Code Integrity is not enabled",
				Path:        `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`,
				Details: map[string]interface{}{
					"recommendation": "Enable HVCI for kernel protection",
				},
			})
		}
	}

	// Check Credential Guard
	output, err = s.ExecCommand(ctx, "reg", "query",
		`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "/v", "LsaCfgFlags")
	if err == nil {
		if strings.Contains(output, "0x0") {
			findings = append(findings, &entity.Finding{
				ID:          "winkernel-credguard-disabled",
				Category:    entity.CategoryRootkit,
				Severity:    entity.SeverityLow,
				Title:       "Credential Guard not enabled",
				Description: "Windows Credential Guard is not enabled",
				Path:        `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`,
				Details: map[string]interface{}{
					"recommendation": "Enable Credential Guard to protect credentials",
				},
			})
		}
	}

	return findings
}

func (s *WindowsKernelScanner) checkDriverCallbacks(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check for potential callback abuse via registry
	// Drivers that register for various notifications can be abused

	// Check for notify routine registrations via common registry indicators
	callbackKeys := []struct {
		key         string
		description string
		severity    entity.Severity
	}{
		{
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
			"IFEO can be used to intercept process creation",
			entity.SeverityHigh,
		},
		{
			`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit`,
			"Silent process exit monitoring can capture process termination",
			entity.SeverityHigh,
		},
		{
			`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls`,
			"AppCertDLLs inject into every process",
			entity.SeverityCritical,
		},
	}

	for _, callback := range callbackKeys {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		output, err := s.ExecCommand(ctx, "reg", "query", callback.key)
		if err != nil {
			continue
		}

		// If key exists and has values, it might be abuse
		if strings.Contains(output, "REG_") {
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "HKEY_") {
					continue
				}

				// Skip default/empty values
				if strings.Contains(line, "(Default)") && strings.Contains(line, "value not set") {
					continue
				}

				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("winkernel-callback-%s", sanitizeID(callback.key)),
					Category:    entity.CategoryRootkit,
					Severity:    callback.severity,
					Title:       "Potential callback abuse detected",
					Description: callback.description,
					Path:        callback.key,
					Details: map[string]interface{}{
						"registry_key": callback.key,
						"entry":        line,
					},
				})
				break
			}
		}
	}

	return findings
}

func (s *WindowsKernelScanner) checkWMIPersistence(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check for WMI event subscriptions (common persistence mechanism)
	// These can run arbitrary code when certain events occur

	// Check for __EventFilter objects
	output, err := s.ExecCommand(ctx, "powershell", "-Command",
		"Get-WmiObject -Namespace root\\subscription -Class __EventFilter 2>$null | Select-Object Name,Query | Format-List")
	if err == nil && strings.TrimSpace(output) != "" {
		// Parse WMI event filters
		filters := strings.Split(output, "Name")
		for _, filter := range filters {
			if strings.TrimSpace(filter) == "" {
				continue
			}

			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winkernel-wmi-filter-%s", sanitizeID(filter[:min(20, len(filter))])),
				Category:    entity.CategoryPersistence,
				Severity:    entity.SeverityHigh,
				Title:       "WMI event filter detected",
				Description: "WMI event subscription can execute code on system events",
				Path:        "root\\subscription\\__EventFilter",
				Details: map[string]interface{}{
					"filter":    strings.TrimSpace(filter),
					"technique": "T1546.003 - WMI Event Subscription",
				},
			})
		}
	}

	// Check for __EventConsumer objects (what runs when filter triggers)
	output, err = s.ExecCommand(ctx, "powershell", "-Command",
		"Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer 2>$null | Select-Object Name,CommandLineTemplate | Format-List")
	if err == nil && strings.TrimSpace(output) != "" {
		consumers := strings.Split(output, "Name")
		for _, consumer := range consumers {
			if strings.TrimSpace(consumer) == "" {
				continue
			}

			// Check for suspicious command lines
			consumerLower := strings.ToLower(consumer)
			severity := entity.SeverityHigh
			if strings.Contains(consumerLower, "powershell") ||
				strings.Contains(consumerLower, "cmd") ||
				strings.Contains(consumerLower, "wscript") {
				severity = entity.SeverityCritical
			}

			findings = append(findings, &entity.Finding{
				ID:          fmt.Sprintf("winkernel-wmi-consumer-%s", sanitizeID(consumer[:min(20, len(consumer))])),
				Category:    entity.CategoryPersistence,
				Severity:    severity,
				Title:       "WMI command consumer detected",
				Description: "WMI consumer executes commands on event triggers",
				Path:        "root\\subscription\\CommandLineEventConsumer",
				Details: map[string]interface{}{
					"consumer":  strings.TrimSpace(consumer),
					"technique": "T1546.003 - WMI Event Subscription",
				},
			})
		}
	}

	return findings
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
