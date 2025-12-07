package scanner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

// KernelScanner detects suspicious kernel modules and rootkits
type KernelScanner struct {
	BaseScanner
}

// Known rootkit module names and suspicious patterns
var (
	knownRootkitModules = map[string]string{
		"reptile":      "Reptile LKM rootkit",
		"diamorphine":  "Diamorphine LKM rootkit",
		"suterusu":     "Suterusu LKM rootkit",
		"adore-ng":     "Adore-NG LKM rootkit",
		"knark":        "Knark LKM rootkit",
		"rkkit":        "Generic rootkit module",
		"heroin":       "Heroin LKM rootkit",
		"rkit":         "Generic rootkit module",
		"hideme":       "Process hiding module",
		"hide_module":  "Module hiding rootkit",
		"modhide":      "Module hiding rootkit",
		"kovid":        "KoviD LKM rootkit",
		"bdvl":         "BDVL LKM rootkit",
		"puszek":       "Puszek LKM rootkit",
		"enyelkm":      "Enye LKM rootkit",
	}

	// Suspicious module parameter patterns
	suspiciousParams = []string{
		"stealth",
		"rootshell",
		"reverseshell",
	}

	// Legitimate parameters that contain suspicious-looking words but are safe
	// e.g., kvm's enable_vmware_backdoor is for VMware compatibility, not a backdoor
	legitimateParams = map[string]map[string]bool{
		"kvm": {
			"enable_vmware_backdoor": true, // VMware compatibility, not a backdoor
		},
		"smartpqi": {
			"hide_vsep": true, // Storage controller parameter
		},
	}
)

func NewKernelScanner() *KernelScanner {
	return &KernelScanner{
		BaseScanner: NewBaseScanner("kernel", "Kernel module and rootkit detector"),
	}
}

func (s *KernelScanner) Category() entity.FindingCategory {
	return entity.CategoryKernel
}

func (s *KernelScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.log.Debug("starting kernel module scan")
	var findings []*entity.Finding

	// Check for known rootkit modules
	if f := s.checkRootkitModules(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Compare /proc/modules with /sys/module for hidden modules
	if f := s.detectHiddenModules(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check module parameters for suspicious values
	if f := s.checkModuleParameters(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check for unsigned modules (if signature enforcement is on)
	if f := s.checkModuleSignatures(ctx); f != nil {
		findings = append(findings, f...)
	}

	// Check /proc/kallsyms for hooked syscalls
	if f := s.checkSyscallHooks(ctx); f != nil {
		findings = append(findings, f...)
	}

	s.log.Debug("kernel scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *KernelScanner) checkRootkitModules(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	file, err := os.Open("/proc/modules")
	if err != nil {
		s.log.Debug("cannot read /proc/modules", zap.Error(err))
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}

		moduleName := strings.ToLower(fields[0])

		// Check against known rootkit modules
		for rootkit, description := range knownRootkitModules {
			if strings.Contains(moduleName, rootkit) {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("kernel-rootkit-%s", moduleName),
					Category:    "kernel",
					Severity:    entity.SeverityCritical,
					Title:       "Known rootkit module detected",
					Description: fmt.Sprintf("Module '%s' matches known rootkit: %s", fields[0], description),
					Path:        "/proc/modules",
					Details: map[string]interface{}{
						"module":       fields[0],
						"rootkit_type": description,
						"full_line":    line,
					},
				})
			}
		}
	}

	return findings
}

func (s *KernelScanner) detectHiddenModules(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Get modules from /proc/modules
	procModules := make(map[string]bool)
	file, err := os.Open("/proc/modules")
	if err != nil {
		s.log.Debug("cannot read /proc/modules", zap.Error(err))
		return nil
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 {
			procModules[fields[0]] = true
		}
	}
	file.Close()

	// Get modules from /sys/module
	sysModules, err := os.ReadDir("/sys/module")
	if err != nil {
		s.log.Debug("cannot read /sys/module", zap.Error(err))
		return nil
	}

	// Modules in /sys/module but not in /proc/modules could be hidden
	for _, entry := range sysModules {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !entry.IsDir() {
			continue
		}

		modName := entry.Name()

		// Check if this module has a refcnt file (indicates it's a loadable module)
		refcntPath := filepath.Join("/sys/module", modName, "refcnt")
		if _, err := os.Stat(refcntPath); err == nil {
			// It's a loadable module, should be in /proc/modules
			if !procModules[modName] {
				findings = append(findings, &entity.Finding{
					ID:          fmt.Sprintf("kernel-hidden-%s", modName),
					Category:    "kernel",
					Severity:    entity.SeverityCritical,
					Title:       "Potentially hidden kernel module",
					Description: fmt.Sprintf("Module '%s' exists in /sys/module but not in /proc/modules - may be hiding", modName),
					Path:        filepath.Join("/sys/module", modName),
					Details: map[string]interface{}{
						"module":       modName,
						"in_proc":      false,
						"in_sys":       true,
						"has_refcnt":   true,
						"technique":    "Module list manipulation",
					},
				})
			}
		}
	}

	return findings
}

func (s *KernelScanner) checkModuleParameters(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	sysModules, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil
	}

	for _, entry := range sysModules {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if !entry.IsDir() {
			continue
		}

		modName := entry.Name()
		paramsDir := filepath.Join("/sys/module", modName, "parameters")

		params, err := os.ReadDir(paramsDir)
		if err != nil {
			continue
		}

		for _, param := range params {
			paramName := strings.ToLower(param.Name())

			// Check against whitelist first
			if modWhitelist, ok := legitimateParams[modName]; ok {
				if modWhitelist[param.Name()] {
					continue // Skip whitelisted parameter
				}
			}

			// Check for suspicious parameter names
			for _, suspicious := range suspiciousParams {
				if strings.Contains(paramName, suspicious) {
					// Read parameter value
					paramPath := filepath.Join(paramsDir, param.Name())
					value, _ := os.ReadFile(paramPath)

					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("kernel-susparam-%s-%s", modName, param.Name()),
						Category:    "kernel",
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious kernel module parameter",
						Description: fmt.Sprintf("Module '%s' has suspicious parameter '%s'", modName, param.Name()),
						Path:        paramPath,
						Details: map[string]interface{}{
							"module":    modName,
							"parameter": param.Name(),
							"value":     strings.TrimSpace(string(value)),
							"pattern":   suspicious,
						},
					})
					break
				}
			}
		}
	}

	return findings
}

func (s *KernelScanner) checkModuleSignatures(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Check if module signature enforcement is enabled
	enforcePath := "/sys/module/module/parameters/sig_enforce"
	enforceData, err := os.ReadFile(enforcePath)
	if err != nil {
		s.log.Debug("cannot check module signature enforcement", zap.Error(err))
		return nil
	}

	sigEnforce := strings.TrimSpace(string(enforceData))

	// If signature enforcement is off, that's a finding
	if sigEnforce == "N" || sigEnforce == "0" {
		findings = append(findings, &entity.Finding{
			ID:          "kernel-sig-enforce-off",
			Category:    "kernel",
			Severity:    entity.SeverityMedium,
			Title:       "Kernel module signature enforcement disabled",
			Description: "Module signature verification is not enforced, allowing unsigned modules to load",
			Path:        enforcePath,
			Details: map[string]interface{}{
				"sig_enforce": sigEnforce,
				"risk":        "Unsigned/malicious modules can be loaded",
			},
		})
	}

	return findings
}

func (s *KernelScanner) checkSyscallHooks(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	// Read /proc/kallsyms to check for syscall table manipulation
	// This is a basic check - sophisticated rootkits may hide this
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		s.log.Debug("cannot read /proc/kallsyms", zap.Error(err))
		return nil
	}
	defer file.Close()

	// Only look for very specific rootkit-related symbols
	// Note: Many "suspicious" looking names are legitimate kernel functions
	// (e.g., orig_insn, hijack_return_addr are part of uprobes/ftrace)
	// Exclude legitimate functions containing "backdoor" like vmw_disable_backdoor (VMware)
	suspiciousSymbols := []string{
		"rootkit_",
		"keylog_",
		"hide_pid_",
		"hide_process_",
		"lkm_backdoor",
	}

	// Whitelist of legitimate kernel symbols that contain suspicious words
	legitimateSymbols := []string{
		"vmw_disable_backdoor",  // VMware backdoor channel management
		"vmw_enable_backdoor",   // VMware backdoor channel management
		"vmw_backdoor",          // VMware guest/host communication channel
		"vmware_backdoor",       // VMware hypercall interface
		"vmw_send_msg_backdoor", // VMware messaging via backdoor channel
		"vmw_recv_msg_backdoor", // VMware messaging via backdoor channel
	}

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		// Limit scanning to prevent long execution
		lineCount++
		if lineCount > 100000 {
			break
		}

		line := scanner.Text()
		lineLower := strings.ToLower(line)

		// Check against whitelist first
		isWhitelisted := false
		for _, legit := range legitimateSymbols {
			if strings.Contains(lineLower, legit) {
				isWhitelisted = true
				break
			}
		}
		if isWhitelisted {
			continue
		}

		for _, suspicious := range suspiciousSymbols {
			if strings.Contains(lineLower, suspicious) {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					findings = append(findings, &entity.Finding{
						ID:          fmt.Sprintf("kernel-hook-%s", fields[2]),
						Category:    "kernel",
						Severity:    entity.SeverityHigh,
						Title:       "Suspicious kernel symbol detected",
						Description: fmt.Sprintf("Symbol '%s' may indicate rootkit presence", fields[2]),
						Path:        "/proc/kallsyms",
						Details: map[string]interface{}{
							"symbol":  fields[2],
							"address": fields[0],
							"type":    fields[1],
							"pattern": suspicious,
						},
					})
				}
				break
			}
		}
	}

	return findings
}
