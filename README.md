# SentinelGuard

A comprehensive security scanner for Linux and Windows systems written in Go. SentinelGuard performs deep inspection of your system to detect backdoors, rootkits, persistence mechanisms, malicious files, and security misconfigurations.

## Features

- **16 Security Scanners** covering network, processes, filesystem, authentication, and more
- **Full Windows Support** with registry, memory injection, and kernel/driver scanning
- **Cross-Platform Architecture** with strategy pattern for OS-specific implementations
- **Multiple Output Formats** - Console (colored), JSON, YAML
- **Concurrent Scanning** with configurable parallelism
- **Low False Positive Rate** through intelligent pattern matching and whitelisting
- **WSL/Docker/Container Aware** - adapts behavior based on environment
- **No External Dependencies** at runtime - single binary deployment

## Scanners

### Cross-Platform Scanners

| Scanner | Description |
|---------|-------------|
| `network` | Suspicious connections, listening ports, reverse shells |
| `process` | Malicious processes, cryptocurrency miners, shell spawns |
| `ssh` | SSH misconfigurations, unauthorized keys, weak settings |
| `filesystem` | SUID/SGID anomalies, hidden files, world-writable dirs |
| `user` | Suspicious accounts, UID 0 users, empty passwords |
| `persistence` | Startup scripts, systemd units, LD_PRELOAD hooks |
| `pdf` | Malicious PDF detection (JavaScript, exploits, payloads) |

### Linux-Specific Scanners

| Scanner | Description |
|---------|-------------|
| `cron` | Suspicious cron jobs and scheduled tasks |
| `kernel` | Rootkit detection, hidden kernel modules, syscall hooks |
| `pam` | PAM backdoors, authentication bypass |
| `memory` | Process injection, hidden processes, LD_PRELOAD |
| `integrity` | Binary tampering, package verification |
| `boot` | Boot persistence, GRUB/initramfs modifications |

### Windows-Specific Scanners

| Scanner | Description |
|---------|-------------|
| `windows-registry` | Registry persistence, startup keys, COM hijacking, AppInit DLLs, IFEO injection |
| `windows-memory` | Process injection, hollowing, suspicious parent-child, typosquatting, credential dumping |
| `windows-kernel` | Driver rootkits, unsigned drivers, minifilters, WMI persistence, kernel integrity |

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/sosalejandro/sentinelguard.git
cd sentinelguard

# Build
go build -o sentinelguard ./cmd/checker/

# Install (optional)
sudo mv sentinelguard /usr/local/bin/
```

### Requirements

- Go 1.21 or later (for building)
- Linux or Windows
- Root/Administrator access recommended for full scanning capabilities

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

### Linux Kernel Scanner
- Hidden kernel modules
- Known rootkit signatures (Reptile, Diamorphine, etc.)
- Suspicious module parameters
- Syscall hooking detection
- Module signature enforcement

### Linux Memory Scanner
- Hidden processes (proc vs ps comparison)
- Deleted executables
- LD_PRELOAD injection
- Suspicious library mappings
- Process name spoofing
- ptrace attachment detection

### Windows Registry Scanner
- Startup/Run key persistence (8+ registry locations)
- Winlogon Shell/Userinit hijacking
- Image File Execution Options (IFEO) debugger injection
- AppInit_DLLs system-wide injection
- COM object hijacking
- Browser Helper Objects (BHO)
- Credential provider abuse
- LSA security/authentication packages
- 18+ malicious pattern detections including:
  - Encoded PowerShell commands
  - Download cradles (certutil, bitsadmin)
  - Living-off-the-land binaries (mshta, regsvr32, rundll32)

### Windows Memory/Process Scanner
- Suspicious parent-child relationships (Office spawning cmd/PowerShell)
- System processes with wrong parents (lsass, csrss, services.exe)
- Process name typosquatting (svch0st.exe, lsasss.exe)
- 25+ suspicious command line patterns
- Credential dumping detection (mimikatz, procdump lsass)
- Process hollowing indicators
- Multiple singleton process detection
- Dangerous privilege detection (SeDebugPrivilege, SeTcbPrivilege)
- Suspicious DLL injection in system processes

### Windows Kernel/Driver Scanner
- Known rootkit driver detection
- Drivers from suspicious paths
- System drivers in wrong locations
- Driver signing enforcement (testsigning, nointegritychecks)
- Kernel debug mode detection
- Suspicious minifilter altitudes
- Hidden/dormant driver detection
- Secure Boot status
- HVCI and Credential Guard status
- Callback abuse (IFEO, SilentProcessExit, AppCertDLLs)
- WMI event subscription persistence

## MITRE ATT&CK Coverage

SentinelGuard detects techniques from multiple ATT&CK categories:

| Technique ID | Name |
|--------------|------|
| T1546.010 | AppInit DLLs |
| T1546.012 | Image File Execution Options Injection |
| T1546.003 | WMI Event Subscription |
| T1546.015 | COM Hijacking |
| T1055 | Process Injection |
| T1055.012 | Process Hollowing |
| T1036.005 | Masquerading: Match Legitimate Name |
| T1059 | Command and Scripting Interpreter |
| T1003 | OS Credential Dumping |
| T1547.001 | Registry Run Keys / Startup Folder |

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

### Cron Job / Scheduled Task

```bash
# Linux: Daily security scan
0 2 * * * /usr/local/bin/sentinelguard scan -f json >> /var/log/sentinelguard.log 2>&1
```

```powershell
# Windows: Create scheduled task
schtasks /create /tn "SentinelGuard Daily Scan" /tr "sentinelguard.exe scan -f json" /sc daily /st 02:00
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

- **Run as root/Administrator** for complete system visibility
- **Audit mode**: Use `-f json` for forensic logging
- **Network scanning** may trigger IDS alerts in monitored environments
- **PDF scanning** reads file contents - ensure appropriate permissions
- **Windows registry scanning** requires appropriate permissions for HKLM keys

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
