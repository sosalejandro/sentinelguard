package scanner

import (
	"context"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"go.uber.org/zap"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

type NetworkScanner struct {
	BaseScanner
}

func NewNetworkScanner() *NetworkScanner {
	return &NetworkScanner{
		BaseScanner: NewBaseScanner("network", "Scans for suspicious network connections and listening ports"),
	}
}

func (s *NetworkScanner) Category() entity.FindingCategory {
	return entity.CategoryNetwork
}

// Suspicious ports commonly used by malware
var suspiciousPorts = map[int]string{
	4444:  "Metasploit default",
	5555:  "Android ADB",
	6666:  "IRC backdoor",
	6667:  "IRC",
	31337: "Back Orifice",
	12345: "NetBus",
	27374: "SubSeven",
	1234:  "Common backdoor",
	9001:  "Tor default",
	1337:  "Elite/leet backdoor",
	3389:  "RDP (verify if expected)",
	5900:  "VNC (verify if expected)",
	8545:  "Ethereum RPC (cryptominer)",
	14444: "Monero mining pool",
	45700: "Stratum mining",
}

// Expanded suspicious IP ranges
var suspiciousIPPrefixes = map[string]string{
	// Tor exit nodes (common ranges)
	"185.220.": "Known Tor exit node range",
	"185.129.": "Known Tor exit node range",
	"176.10.":  "Known Tor exit node range",
	"199.249.": "Known Tor exit node range",
	// Known malware/C2 ranges
	"45.33.":   "Linode range (common C2 hosting)",
	"45.77.":   "Vultr range (common C2 hosting)",
	"45.32.":   "Vultr range (common C2 hosting)",
	"104.238.": "Vultr range (common C2 hosting)",
	"198.98.":  "Known bulletproof hosting",
	"185.234.": "Known bulletproof hosting",
	// Russia-based bulletproof hosting
	"91.218.": "Eastern European hosting (verify)",
	"91.219.": "Eastern European hosting (verify)",
	// Known cryptomining pools
	"142.4.":   "OVH range (verify - common mining pool host)",
	"144.217.": "OVH range (verify - common mining pool host)",
}

func (s *NetworkScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting network scan")

	var findings []*entity.Finding

	// Platform-specific scanning
	if runtime.GOOS == "windows" {
		findings = s.scanWindows(ctx)
	} else {
		findings = s.scanUnix(ctx)
	}

	s.Logger().Debug("network scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

// scanUnix performs network scanning on Linux/macOS using ss or netstat
func (s *NetworkScanner) scanUnix(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	listeningFindings := s.scanListeningPortsUnix(ctx)
	findings = append(findings, listeningFindings...)

	establishedFindings := s.scanEstablishedConnectionsUnix(ctx)
	findings = append(findings, establishedFindings...)

	return findings
}

// scanWindows performs network scanning on Windows using netstat
func (s *NetworkScanner) scanWindows(ctx context.Context) []*entity.Finding {
	var findings []*entity.Finding

	listeningFindings := s.scanListeningPortsWindows(ctx)
	findings = append(findings, listeningFindings...)

	establishedFindings := s.scanEstablishedConnectionsWindows(ctx)
	findings = append(findings, establishedFindings...)

	return findings
}

func (s *NetworkScanner) scanListeningPortsUnix(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning listening ports (Unix)")

	// Try ss first, fall back to netstat
	lines, err := s.RunCommand(ctx, "ss", "-tulpn")
	if err != nil {
		lines, err = s.RunCommand(ctx, "netstat", "-tulpn")
		if err != nil {
			s.Logger().Debug("failed to get listening ports", zap.Error(err))
			return nil
		}
	}

	return s.analyzeListeningPorts(lines, false)
}

func (s *NetworkScanner) scanListeningPortsWindows(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning listening ports (Windows)")

	lines, err := s.RunCommand(ctx, "netstat", "-ano")
	if err != nil {
		s.Logger().Debug("failed to get listening ports", zap.Error(err))
		return nil
	}

	return s.analyzeListeningPorts(lines, true)
}

func (s *NetworkScanner) analyzeListeningPorts(lines []string, isWindows bool) []*entity.Finding {
	var findings []*entity.Finding

	for _, line := range lines {
		// Skip headers
		if strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") ||
			strings.HasPrefix(line, "Proto") || strings.HasPrefix(line, "Active") {
			continue
		}

		// For Windows, only look at LISTENING state
		if isWindows && !strings.Contains(line, "LISTENING") {
			continue
		}

		port, addr := s.parseListeningLine(line, isWindows)
		if port == 0 {
			continue
		}

		s.Logger().Debug("found listening port",
			zap.Int("port", port),
			zap.String("address", addr),
		)

		if reason, suspicious := suspiciousPorts[port]; suspicious {
			finding := entity.NewFinding(
				entity.CategoryNetwork,
				entity.SeverityHigh,
				"Suspicious listening port detected",
				"Port "+strconv.Itoa(port)+" is commonly used by malware: "+reason,
			).WithDetail("port", port).
				WithDetail("address", addr).
				WithDetail("reason", reason)
			findings = append(findings, finding)
		}

		if addr == "0.0.0.0" || addr == "*" || addr == "::" || addr == "[::]" {
			if !s.isKnownService(port) {
				finding := entity.NewFinding(
					entity.CategoryNetwork,
					entity.SeverityMedium,
					"Service listening on all interfaces",
					"Port "+strconv.Itoa(port)+" is listening on all network interfaces",
				).WithDetail("port", port).
					WithDetail("address", addr)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

func (s *NetworkScanner) scanEstablishedConnectionsUnix(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning established connections (Unix)")

	lines, err := s.RunCommand(ctx, "ss", "-tnp")
	if err != nil {
		lines, err = s.RunCommand(ctx, "netstat", "-tnp")
		if err != nil {
			return nil
		}
	}

	return s.analyzeEstablishedConnections(lines, false)
}

func (s *NetworkScanner) scanEstablishedConnectionsWindows(ctx context.Context) []*entity.Finding {
	s.Logger().Debug("scanning established connections (Windows)")

	lines, err := s.RunCommand(ctx, "netstat", "-ano")
	if err != nil {
		return nil
	}

	return s.analyzeEstablishedConnections(lines, true)
}

func (s *NetworkScanner) analyzeEstablishedConnections(lines []string, isWindows bool) []*entity.Finding {
	var findings []*entity.Finding

	for _, line := range lines {
		if !strings.Contains(line, "ESTAB") && !strings.Contains(line, "ESTABLISHED") {
			continue
		}

		remoteIP, remotePort := s.parseRemoteAddress(line, isWindows)
		if remoteIP == "" {
			continue
		}

		// Check for suspicious IP prefixes
		for prefix, reason := range suspiciousIPPrefixes {
			if strings.HasPrefix(remoteIP, prefix) {
				finding := entity.NewFinding(
					entity.CategoryNetwork,
					entity.SeverityCritical,
					"Connection to suspicious IP detected",
					"Established connection to "+remoteIP+": "+reason,
				).WithDetail("remote_ip", remoteIP).
					WithDetail("remote_port", remotePort).
					WithDetail("reason", reason).
					WithDetail("raw_line", line)
				findings = append(findings, finding)
			}
		}

		// Check for connections to suspicious ports
		if reason, suspicious := suspiciousPorts[remotePort]; suspicious {
			finding := entity.NewFinding(
				entity.CategoryNetwork,
				entity.SeverityHigh,
				"Connection to suspicious remote port",
				"Connection to port "+strconv.Itoa(remotePort)+": "+reason,
			).WithDetail("remote_ip", remoteIP).
				WithDetail("remote_port", remotePort).
				WithDetail("reason", reason)
			findings = append(findings, finding)
		}
	}

	return findings
}

func (s *NetworkScanner) parseListeningLine(line string, isWindows bool) (int, string) {
	if isWindows {
		// Windows netstat format: Proto  Local Address          Foreign Address        State           PID
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return 0, ""
		}
		return parseAddressPortPair(fields[1])
	}

	// Unix ss/netstat format
	re := regexp.MustCompile(`(\S+):(\d+)\s+`)
	matches := re.FindStringSubmatch(line)
	if len(matches) < 3 {
		return 0, ""
	}

	port, err := strconv.Atoi(matches[2])
	if err != nil {
		return 0, ""
	}

	return port, matches[1]
}

func (s *NetworkScanner) parseRemoteAddress(line string, isWindows bool) (string, int) {
	fields := strings.Fields(line)

	if isWindows {
		// Windows: Proto  Local Address          Foreign Address        State           PID
		if len(fields) < 3 {
			return "", 0
		}
		port, addr := parseAddressPortPair(fields[2])
		return addr, port
	}

	// Unix format varies, look for IP:port pattern
	for _, field := range fields {
		if strings.Contains(field, ":") && !strings.HasPrefix(field, "0.0.0.0") && !strings.HasPrefix(field, "127.") && !strings.HasPrefix(field, "*") {
			parts := strings.Split(field, ":")
			if len(parts) >= 2 {
				port, _ := strconv.Atoi(parts[len(parts)-1])
				ip := strings.Join(parts[:len(parts)-1], ":")
				return ip, port
			}
		}
	}
	return "", 0
}

// parseAddressPortPair parses "addr:port" format for both IPv4 and IPv6
func parseAddressPortPair(addrPort string) (int, string) {
	// Handle IPv6 bracket notation [::1]:port
	if strings.HasPrefix(addrPort, "[") {
		closeBracket := strings.LastIndex(addrPort, "]")
		if closeBracket != -1 {
			addr := addrPort[1:closeBracket]
			if colonIdx := strings.LastIndex(addrPort[closeBracket:], ":"); colonIdx != -1 {
				port, _ := strconv.Atoi(addrPort[closeBracket+colonIdx+1:])
				return port, addr
			}
		}
	}

	// IPv4 format addr:port
	lastColon := strings.LastIndex(addrPort, ":")
	if lastColon != -1 {
		port, _ := strconv.Atoi(addrPort[lastColon+1:])
		return port, addrPort[:lastColon]
	}

	return 0, ""
}

func (s *NetworkScanner) isKnownService(port int) bool {
	knownPorts := map[int]bool{
		22: true, 53: true, 80: true, 443: true,
		3306: true, 5432: true, 6379: true, 27017: true,
		8080: true, 8443: true, 9090: true,
		25: true, 110: true, 143: true, 587: true, 993: true, 995: true, // Mail
		21: true, 69: true, // FTP/TFTP
		123: true, 161: true, 162: true, // NTP/SNMP
		389: true, 636: true, // LDAP
		1433: true, 1521: true, // MSSQL/Oracle
		5672: true, 15672: true, // RabbitMQ
		9200: true, 9300: true, // Elasticsearch
		2181: true, 2888: true, 3888: true, // Zookeeper
		6443: true, 10250: true, // Kubernetes
	}
	return knownPorts[port]
}
