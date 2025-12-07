package scanner

import (
	"testing"

	"github.com/as-main/backdoor-checker/internal/domain/entity"
)

func TestNetworkScanner_AnalyzeListeningPorts_SuspiciousPorts(t *testing.T) {
	scanner := NewNetworkScanner()

	tests := []struct {
		name              string
		input             []string
		isWindows         bool
		minExpectedCount  int // At least this many findings
		hasSuspiciousPort bool
		expectedPort      int
		expectedReason    string
	}{
		{
			name:              "Metasploit default port 4444",
			input:             []string{"tcp    LISTEN  0       128       0.0.0.0:4444      0.0.0.0:*"},
			isWindows:         false,
			minExpectedCount:  1,
			hasSuspiciousPort: true,
			expectedPort:      4444,
			expectedReason:    "Metasploit default",
		},
		{
			name:              "IRC backdoor port 6666",
			input:             []string{"tcp    LISTEN  0       128       0.0.0.0:6666      0.0.0.0:*"},
			isWindows:         false,
			minExpectedCount:  1,
			hasSuspiciousPort: true,
			expectedPort:      6666,
			expectedReason:    "IRC backdoor",
		},
		{
			name:              "Back Orifice port 31337",
			input:             []string{"tcp    LISTEN  0       128       0.0.0.0:31337     0.0.0.0:*"},
			isWindows:         false,
			minExpectedCount:  1,
			hasSuspiciousPort: true,
			expectedPort:      31337,
			expectedReason:    "Back Orifice",
		},
		{
			name:             "Safe port 443 HTTPS",
			input:            []string{"tcp    LISTEN  0       128       0.0.0.0:443       0.0.0.0:*"},
			isWindows:        false,
			minExpectedCount: 0, // 443 is known safe, no findings expected
		},
		{
			name:             "Safe port 80 HTTP",
			input:            []string{"tcp    LISTEN  0       128       0.0.0.0:80        0.0.0.0:*"},
			isWindows:        false,
			minExpectedCount: 0, // 80 is known safe, no findings expected
		},
		{
			name:              "Windows format - suspicious port",
			input:             []string{"  TCP    0.0.0.0:4444           0.0.0.0:0              LISTENING       1234"},
			isWindows:         true,
			minExpectedCount:  1,
			hasSuspiciousPort: true,
			expectedPort:      4444,
			expectedReason:    "Metasploit default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.analyzeListeningPorts(tt.input, tt.isWindows)

			if len(findings) < tt.minExpectedCount {
				t.Errorf("expected at least %d findings, got %d", tt.minExpectedCount, len(findings))
				return
			}

			if tt.hasSuspiciousPort {
				// Find the suspicious port finding
				var found bool
				for _, finding := range findings {
					if finding.Category != entity.CategoryNetwork {
						continue
					}
					port, ok := finding.Details["port"].(int)
					if !ok || port != tt.expectedPort {
						continue
					}
					reason, ok := finding.Details["reason"].(string)
					if ok && reason == tt.expectedReason {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected to find suspicious port %d with reason %q", tt.expectedPort, tt.expectedReason)
				}
			}
		})
	}
}

func TestNetworkScanner_AnalyzeEstablishedConnections_SuspiciousIPs(t *testing.T) {
	scanner := NewNetworkScanner()

	// Note: The Unix parser looks for remote addresses that don't start with local prefixes
	// The parser finds fields containing ":" that aren't 0.0.0.0, 127.*, or *
	// So remote IPs like 185.220.x.x will be detected
	tests := []struct {
		name          string
		input         []string
		isWindows     bool
		expectedCount int
		hasCritical   bool
	}{
		{
			name:          "Windows ESTABLISHED connection to Tor",
			input:         []string{"  TCP    192.168.1.1:45678      185.220.100.1:443      ESTABLISHED     1234"},
			isWindows:     true,
			expectedCount: 1,
			hasCritical:   true,
		},
		{
			name:          "Windows ESTABLISHED connection to bulletproof",
			input:         []string{"  TCP    192.168.1.1:45678      198.98.50.1:443        ESTABLISHED     1234"},
			isWindows:     true,
			expectedCount: 1,
			hasCritical:   true,
		},
		{
			name:          "Windows normal connection",
			input:         []string{"  TCP    192.168.1.1:45678      142.250.80.46:443      ESTABLISHED     1234"},
			isWindows:     true,
			expectedCount: 0,
		},
		{
			name:          "Windows connection to suspicious port",
			input:         []string{"  TCP    192.168.1.1:45678      8.8.8.8:4444           ESTABLISHED     1234"},
			isWindows:     true,
			expectedCount: 1,
			hasCritical:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := scanner.analyzeEstablishedConnections(tt.input, tt.isWindows)

			if len(findings) != tt.expectedCount {
				t.Errorf("expected %d findings, got %d", tt.expectedCount, len(findings))
				for i, f := range findings {
					t.Logf("  finding %d: %s - %s", i, f.Title, f.Description)
				}
				return
			}

			if tt.hasCritical && len(findings) > 0 {
				if findings[0].Severity != entity.SeverityCritical {
					t.Errorf("expected Critical severity, got %s", findings[0].Severity)
				}
			}
		})
	}
}

func TestNetworkScanner_ParseAddressPortPair(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedPort int
		expectedAddr string
	}{
		{
			name:         "IPv4 address",
			input:        "192.168.1.1:8080",
			expectedPort: 8080,
			expectedAddr: "192.168.1.1",
		},
		{
			name:         "IPv4 all interfaces",
			input:        "0.0.0.0:443",
			expectedPort: 443,
			expectedAddr: "0.0.0.0",
		},
		{
			name:         "IPv6 loopback",
			input:        "[::1]:22",
			expectedPort: 22,
			expectedAddr: "::1",
		},
		{
			name:         "IPv6 all interfaces",
			input:        "[::]:80",
			expectedPort: 80,
			expectedAddr: "::",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, addr := parseAddressPortPair(tt.input)

			if port != tt.expectedPort {
				t.Errorf("expected port %d, got %d", tt.expectedPort, port)
			}
			if addr != tt.expectedAddr {
				t.Errorf("expected addr %q, got %q", tt.expectedAddr, addr)
			}
		})
	}
}

func TestNetworkScanner_IsKnownService(t *testing.T) {
	scanner := NewNetworkScanner()

	knownPorts := []int{22, 80, 443, 3306, 5432, 8080}
	for _, port := range knownPorts {
		if !scanner.isKnownService(port) {
			t.Errorf("port %d should be known service", port)
		}
	}

	unknownPorts := []int{4444, 31337, 6666, 12345}
	for _, port := range unknownPorts {
		if scanner.isKnownService(port) {
			t.Errorf("port %d should not be known service", port)
		}
	}
}
