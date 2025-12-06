# SentinelGuard

A comprehensive security scanner for Linux systems written in Go. SentinelGuard performs deep inspection of your system to detect backdoors, rootkits, persistence mechanisms, malicious files, and security misconfigurations.

## Features

- **13 Security Scanners** covering network, processes, filesystem, authentication, and more
- **Cross-Platform Architecture** with strategy pattern for OS-specific implementations
- **Multiple Output Formats** - Console (colored), JSON, YAML
- **Concurrent Scanning** with configurable parallelism
- **Low False Positive Rate** through intelligent pattern matching and whitelisting
- **WSL/Docker/Container Aware** - adapts behavior based on environment
- **No External Dependencies** at runtime - single binary deployment

## Scanners

| Scanner | Description |
|---------|-------------|
| `network` | Suspicious connections, listening ports, reverse shells |
| `process` | Malicious processes, cryptocurrency miners, shell spawns |
| `cron` | Suspicious cron jobs and scheduled tasks |
| `ssh` | SSH misconfigurations, unauthorized keys, weak settings |
| `persistence` | Startup scripts, systemd units, LD_PRELOAD hooks |
| `filesystem` | SUID/SGID anomalies, hidden files, world-writable dirs |
| `user` | Suspicious accounts, UID 0 users, empty passwords |
| `kernel` | Rootkit detection, hidden kernel modules |
| `pam` | PAM backdoors, authentication bypass |
| `memory` | Process injection, hidden processes |
| `integrity` | Binary tampering, package verification |
| `boot` | Boot persistence, GRUB/initramfs modifications |
| `pdf` | Malicious PDF detection (JavaScript, exploits, payloads) |

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/sentinelguard.git
cd sentinelguard

# Build
go build -o sentinelguard ./cmd/checker/

# Install (optional)
sudo mv sentinelguard /usr/local/bin/
```

### Requirements

- Go 1.21 or later (for building)
- Linux (primary support), macOS/Windows (partial support)
- Root access recommended for full scanning capabilities

## Usage

### Basic Scan

```bash
# Run all scanners
./sentinelguard scan

# Run with verbose output
./sentinelguard scan -v

# Run with debug logging
./sentinelguard scan -d
```

### Selective Scanning

```bash
# Run specific scanners
./sentinelguard scan -s network,process,ssh

# List available scanners
./sentinelguard list
```

### Output Formats

```bash
# Console output (default, colored)
./sentinelguard scan

# JSON output
./sentinelguard scan -f json

# JSON pretty-printed
./sentinelguard scan -f json --pretty

# YAML output
./sentinelguard scan -f yaml

# Save to file
./sentinelguard scan -f json > report.json
```

### PDF Scanner Options

```bash
# Scan default paths (/home, /tmp, /var/tmp)
./sentinelguard scan -s pdf

# Scan specific directories
./sentinelguard scan -s pdf --pdf-paths "/home/user/Downloads,/mnt/shared"

# Scan Windows folders from WSL
./sentinelguard scan -s pdf --pdf-paths "/mnt/c/Users/username/Downloads"
```

### Advanced Options

```bash
# Set scan timeout
./sentinelguard scan -t 10m

# Control parallelism
./sentinelguard scan -p -m 10    # 10 parallel scanners

# Sequential scanning
./sentinelguard scan -p=false
```

## Command Reference

```
sentinelguard [command]

Commands:
  scan        Run security scan for backdoors and suspicious activity
  list        List available scanners
  version     Print version information
  help        Help about any command

Scan Flags:
  -s, --scanners strings    Specific scanners to run (default: all)
  -p, --parallel            Run scanners in parallel (default: true)
  -m, --max-parallel int    Maximum parallel scanners (default: 5)
  -t, --timeout duration    Scan timeout (default: 5m0s)
  -f, --format string       Output format: console, json, yaml (default: "console")
      --pretty              Pretty print JSON output (default: true)
      --pdf-paths strings   Custom paths for PDF scanner
  -v, --verbose             Verbose output
  -d, --debug               Debug logging

Global Flags:
  -h, --help    Help for any command
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings or only low/info severity |
| 1 | High severity findings detected |
| 2 | Critical severity findings detected |

## Output Example

### Console Output

```
╔════════════════════════════════════════════════════════════╗
║           SENTINELGUARD SCAN REPORT                        ║
╚════════════════════════════════════════════════════════════╝

Scan ID:      SCAN-000001
Start Time:   2025-01-15 10:30:00
Duration:     45.2s
Status:       COMPLETED

─── SUMMARY ───────────────────────────────────────────────────

Scanners Executed: 13

Total Findings: 5

  CRITICAL [  0]
  HIGH     [  2] ██
  MEDIUM   [  3] ███
  LOW      [  0]
  INFO     [  0]

─── FINDINGS ──────────────────────────────────────────────────

▸ NETWORK (2)

  [HIGH] Suspicious outbound connection
    Process connecting to known malicious IP range
    Path: /usr/bin/suspicious

  [MEDIUM] Service listening on all interfaces
    Port 8080 is listening on 0.0.0.0
```

### JSON Output

```json
{
  "scan_id": "SCAN-000001",
  "start_time": "2025-01-15T10:30:00-05:00",
  "end_time": "2025-01-15T10:30:45-05:00",
  "duration": "45.2s",
  "status": "COMPLETED",
  "summary": {
    "total_findings": 5,
    "critical_count": 0,
    "high_count": 2,
    "medium_count": 3,
    "low_count": 0,
    "info_count": 0,
    "scanners_executed": ["network", "process", "ssh", "..."]
  },
  "findings": [
    {
      "id": "FIND-000001",
      "category": "NETWORK",
      "severity": "HIGH",
      "title": "Suspicious outbound connection",
      "description": "Process connecting to known malicious IP range",
      "path": "/usr/bin/suspicious",
      "timestamp": "2025-01-15T10:30:15-05:00",
      "details": {
        "remote_ip": "192.168.1.100",
        "remote_port": 4444
      }
    }
  ]
}
```

## Detection Capabilities

### Network Scanner
- Connections to known malicious IP ranges
- Reverse shell patterns (ports 4444, 5555, etc.)
- Suspicious listening services
- Connections to Tor exit nodes
- IRC/botnet communication patterns

### Process Scanner
- Cryptocurrency miners (xmrig, minerd, etc.)
- Known malware process names
- Shell spawned from web servers
- Processes with deleted executables
- Hidden processes (PID gaps)

### PDF Scanner
- JavaScript execution (`/JS`, `/JavaScript`)
- Automatic actions (`/OpenAction`, `/AA`)
- Launch actions (can execute external programs)
- Embedded files and attachments
- Suspicious URLs and data URIs
- Exploit patterns (heap spray, NOP sleds)
- PowerShell/shell command injection

### Persistence Scanner
- Malicious profile scripts (.bashrc, .profile)
- Suspicious systemd services
- LD_PRELOAD hijacking
- Cron-based persistence
- Init script modifications

### Kernel Scanner
- Hidden kernel modules
- Rootkit signatures
- Suspicious module parameters
- Tainted kernel detection

### And More...
Each scanner implements comprehensive detection rules with continuous updates.

## Architecture

```
sentinelguard/
├── cmd/checker/           # CLI application
│   ├── main.go           # Entry point
│   ├── scan.go           # Scan command
│   ├── list.go           # List command
│   └── root.go           # Root command & flags
├── internal/
│   ├── domain/
│   │   ├── entity/       # Core domain models
│   │   └── repository/   # Scanner interface
│   ├── infrastructure/
│   │   ├── platform/     # OS detection & strategies
│   │   ├── reporter/     # Output formatters
│   │   └── scanner/      # Scanner implementations
│   └── usecase/          # Business logic
└── pkg/
    └── logger/           # Logging utilities
```

## Configuration

SentinelGuard follows sensible defaults but can be customized:

### Environment Variables

```bash
# Logging level
export LOG_LEVEL=debug

# Custom scan paths for PDF scanner
export SENTINELGUARD_PDF_PATHS="/custom/path1,/custom/path2"
```

## Integration

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    ./sentinelguard scan -f json > security-report.json
    if [ $? -eq 2 ]; then
      echo "Critical security issues found!"
      exit 1
    fi
```

### Cron Job

```bash
# Daily security scan
0 2 * * * /usr/local/bin/sentinelguard scan -f json >> /var/log/sentinelguard.log 2>&1
```

### Monitoring Integration

```bash
# Output for log aggregators (JSON format)
./sentinelguard scan -f json | jq '.findings[] | select(.severity == "CRITICAL")'
```

## Performance

- Typical full scan: 30-60 seconds
- Parallel execution reduces scan time by 60-70%
- Memory efficient: ~50MB peak usage
- Single binary, no runtime dependencies

## Security Considerations

- **Run as root** for complete system visibility
- **Audit mode**: Use `-f json` for forensic logging
- **Network scanning** may trigger IDS alerts in monitored environments
- **PDF scanning** reads file contents - ensure appropriate permissions

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

### Adding a New Scanner

1. Create scanner in `internal/infrastructure/scanner/`
2. Implement the `Scanner` interface
3. Register in `cmd/checker/scan.go`
4. Add tests and documentation

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for CLI
- Logging powered by [Zap](https://github.com/uber-go/zap)
- Color output via [fatih/color](https://github.com/fatih/color)
