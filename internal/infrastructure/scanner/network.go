package scanner

import (
	"context"
	"regexp"
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

func (s *NetworkScanner) Scan(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("starting network scan")

	var findings []*entity.Finding

	listeningFindings, err := s.scanListeningPorts(ctx)
	if err == nil {
		findings = append(findings, listeningFindings...)
	}

	establishedFindings, err := s.scanEstablishedConnections(ctx)
	if err == nil {
		findings = append(findings, establishedFindings...)
	}

	s.Logger().Debug("network scan completed", zap.Int("findings", len(findings)))
	return findings, nil
}

func (s *NetworkScanner) scanListeningPorts(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("scanning listening ports")

	lines, err := s.RunCommand(ctx, "ss", "-tulpn")
	if err != nil {
		return nil, err
	}

	var findings []*entity.Finding
	suspiciousPorts := map[int]string{
		4444:  "Metasploit default",
		5555:  "Android ADB",
		6666:  "IRC backdoor",
		6667:  "IRC",
		31337: "Back Orifice",
		12345: "NetBus",
		27374: "SubSeven",
		1234:  "Common backdoor",
		9001:  "Tor default",
	}

	for _, line := range lines {
		if strings.HasPrefix(line, "Netid") || strings.HasPrefix(line, "State") {
			continue
		}

		port, addr := s.parseListeningLine(line)
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

		if addr == "0.0.0.0" || addr == "*" || addr == "::" {
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

	return findings, nil
}

func (s *NetworkScanner) scanEstablishedConnections(ctx context.Context) ([]*entity.Finding, error) {
	s.Logger().Debug("scanning established connections")

	lines, err := s.RunCommand(ctx, "ss", "-tnp")
	if err != nil {
		return nil, err
	}

	var findings []*entity.Finding
	suspiciousIPs := map[string]string{
		"185.220.": "Known Tor exit node range",
		"45.33.":   "Known malware C2 range",
	}

	for _, line := range lines {
		if !strings.Contains(line, "ESTAB") {
			continue
		}

		remoteIP := s.parseRemoteIP(line)
		if remoteIP == "" {
			continue
		}

		for prefix, reason := range suspiciousIPs {
			if strings.HasPrefix(remoteIP, prefix) {
				finding := entity.NewFinding(
					entity.CategoryNetwork,
					entity.SeverityCritical,
					"Connection to suspicious IP detected",
					"Established connection to "+remoteIP+": "+reason,
				).WithDetail("remote_ip", remoteIP).
					WithDetail("reason", reason).
					WithDetail("raw_line", line)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

func (s *NetworkScanner) parseListeningLine(line string) (int, string) {
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

func (s *NetworkScanner) parseRemoteIP(line string) string {
	fields := strings.Fields(line)
	for _, field := range fields {
		if strings.Contains(field, ":") && !strings.HasPrefix(field, "0.0.0.0") && !strings.HasPrefix(field, "127.") {
			parts := strings.Split(field, ":")
			if len(parts) >= 1 {
				return parts[0]
			}
		}
	}
	return ""
}

func (s *NetworkScanner) isKnownService(port int) bool {
	knownPorts := map[int]bool{
		22: true, 53: true, 80: true, 443: true,
		3306: true, 5432: true, 6379: true, 27017: true,
		8080: true, 8443: true, 9090: true,
	}
	return knownPorts[port]
}
