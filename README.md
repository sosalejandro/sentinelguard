# SentinelGuard

[![CI](https://github.com/sosalejandro/sentinelguard/actions/workflows/ci.yml/badge.svg)](https://github.com/sosalejandro/sentinelguard/actions/workflows/ci.yml)
[![Release](https://github.com/sosalejandro/sentinelguard/actions/workflows/release.yml/badge.svg)](https://github.com/sosalejandro/sentinelguard/actions/workflows/release.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/sosalejandro/sentinelguard)](https://go.dev/)
[![License](https://img.shields.io/github/license/sosalejandro/sentinelguard)](LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/sosalejandro/sentinelguard)](https://github.com/sosalejandro/sentinelguard/releases/latest)

A comprehensive security scanner for Linux and Windows systems written in Go. SentinelGuard performs deep inspection of your system to detect backdoors, rootkits, persistence mechanisms, malicious files, and security misconfigurations.

## Features

- **17 Security Scanners** covering network, processes, filesystem, authentication, and more
- **Full Windows Support** with registry, memory injection, and kernel/driver scanning (PowerShell-first, WMIC fallback)
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
| `cron` | Suspicious cron jobs, systemd timers, scheduled task analysis |
| `kernel` | Rootkit detection, hidden kernel modules, syscall hooks |
| `pam` | PAM backdoors, authentication bypass |
| `memory` | Process injection, hidden processes, LD_PRELOAD |
| `integrity` | Binary tampering, package verification |
| `boot` | Boot persistence, GRUB/initramfs modifications |
| `container` | Docker/container escape vectors, capability abuse, socket mounts |

### Windows-Specific Scanners

| Scanner | Description |
|---------|-------------|
| `windows-registry` | Registry persistence, startup keys, COM hijacking, AppInit DLLs, IFEO injection, scheduled task scanning |
| `windows-memory` | Process injection, hollowing, suspicious parent-child, typosquatting, credential dumping |
| `windows-kernel` | Driver rootkits, unsigned drivers, minifilters, WMI persistence, kernel integrity |

## Installation

### Pre-built Binaries (Recommended)

Download the latest release for your platform from the [Releases page](https://github.com/sosalejandro/sentinelguard/releases/latest).

#### Linux/macOS

```bash
# Download (replace VERSION and PLATFORM)
curl -LO https://github.com/sosalejandro/sentinelguard/releases/latest/download/sentinelguard_VERSION_linux_amd64.tar.gz

# Extract
tar -xzf sentinelguard_*.tar.gz

# Install
sudo mv sentinelguard /usr/local/bin/

# Verify
sentinelguard version
```

#### Windows

1. Download `sentinelguard_VERSION_windows_amd64.zip` from [Releases](https://github.com/sosalejandro/sentinelguard/releases/latest)
2. Extract the ZIP file
3. Move `sentinelguard.exe` to a directory in your PATH
4. Run from PowerShell or Command Prompt:
   ```powershell
   .\sentinelguard.exe scan
   ```

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

### Using Go Install

```bash
go install github.com/sosalejandro/sentinelguard/cmd/checker@latest
```

### Requirements

- Go 1.21 or later (for building from source)
- Linux, Windows, or macOS
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

### Linux Container Security Scanner
- Privileged container detection (all capabilities)
- Dangerous capability analysis (SYS_ADMIN, SYS_PTRACE, SYS_MODULE, etc.)
- Mounted Docker/containerd socket detection
- Host namespace sharing (PID, network)
- Sensitive host path mounts (/etc, /proc/sys, cgroups)
- Container escape tool detection (docker, kubectl, nsenter)
- Writable /proc/sys/kernel/core_pattern detection
- Raw device access (/dev/sda, /dev/mem)
- Exposed Docker socket permissions on host

### Linux Systemd Timer Scanner
- Comprehensive timer unit analysis
- Service content pattern matching
- Download/execute and reverse shell detection
- Cryptominer detection in timer services
- User-level timer scanning
- Non-standard service location detection

### Windows Registry Scanner
- Startup/Run key persistence (18 registry locations)
- Winlogon Shell/Userinit/Notify hijacking
- Image File Execution Options (IFEO) debugger injection
- AppInit_DLLs system-wide injection
- COM object hijacking with CLSID validation and legitimate whitelist (17+ known CLSIDs)
- Browser Helper Objects (BHO) with legitimate whitelist
- Credential provider abuse
- LSA security/authentication packages
- Group Policy script persistence (scripts.ini)
- Scheduled task content analysis (malicious patterns, suspicious paths, privileged script execution)
- 42+ malicious pattern detections including:
  - Encoded PowerShell commands (-enc, -e, base64)
  - Download cradles (certutil, bitsadmin, curl, wget)
  - Living-off-the-land binaries (mshta, regsvr32, rundll32, cmstp, msiexec)
  - Script interpreters (wscript, cscript, powershell hidden window)
  - Credential access tools (mimikatz, procdump, comsvcs MiniDump)

### Windows Memory/Process Scanner
- Suspicious parent-child relationships (27 validated process trees)
- System processes with wrong parents (lsass, csrss, services.exe, smss, wininit)
- Process name typosquatting (svch0st.exe, lsasss.exe, crsss.exe)
- 52+ suspicious command line patterns including:
  - Credential dumping (mimikatz, procdump, comsvcs, pypykatz, lazagne, ntdsutil)
  - Defense evasion (AMSI bypass, ETW patching, Defender exclusions)
  - Reconnaissance (nltest, dsquery, AdFind, BloodHound)
  - Lateral movement (psexec, wmic shadowcopy, vssadmin)
- Process hollowing indicators
- Multiple singleton process detection
- Dangerous privilege detection (SeDebugPrivilege, SeTcbPrivilege, SeImpersonatePrivilege)
- Suspicious DLL injection in system processes
- PowerShell-based process enumeration with WMIC fallback

### Windows Kernel/Driver Scanner
- 33+ known rootkit driver signatures (Necurs, ZeroAccess, Turla, Uroburos, Regin, FinFisher, etc.)
- Drivers from suspicious paths (temp, appdata, downloads)
- System drivers in wrong locations
- Driver signing enforcement (testsigning, nointegritychecks)
- Kernel debug mode detection
- Suspicious minifilter altitudes
- Hidden/dormant driver detection
- Secure Boot, HVCI, and Credential Guard status
- Callback abuse (IFEO, SilentProcessExit, AppCertDLLs)
- WMI event subscription persistence:
  - CommandLineEventConsumer detection
  - ActiveScriptEventConsumer detection
  - FilterToConsumerBinding analysis

## MITRE ATT&CK Coverage

SentinelGuard detects techniques from multiple ATT&CK categories:

| Technique ID | Name |
|--------------|------|
| T1546.010 | AppInit DLLs |
| T1546.012 | Image File Execution Options Injection |
| T1546.003 | WMI Event Subscription |
| T1546.015 | COM Hijacking |
| T1547.001 | Registry Run Keys / Startup Folder |
| T1547.004 | Winlogon Helper DLL |
| T1547.014 | Active Setup |
| T1055 | Process Injection |
| T1055.012 | Process Hollowing |
| T1036.005 | Masquerading: Match Legitimate Name |
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1003 | OS Credential Dumping |
| T1003.001 | LSASS Memory |
| T1003.003 | NTDS |
| T1562.001 | Disable or Modify Tools (AMSI/ETW) |
| T1087 | Account Discovery |
| T1482 | Domain Trust Discovery |
| T1053.005 | Scheduled Task/Job: Scheduled Task |
| T1611 | Escape to Host (Container) |
| T1610 | Deploy Container |

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

## Development

### Building

```bash
# Build for current platform
go build -o sentinelguard ./cmd/checker/

# Build for specific platform
GOOS=windows GOARCH=amd64 go build -o sentinelguard.exe ./cmd/checker/
GOOS=linux GOARCH=amd64 go build -o sentinelguard ./cmd/checker/
GOOS=darwin GOARCH=arm64 go build -o sentinelguard ./cmd/checker/
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### CI/CD

The project uses GitHub Actions for continuous integration and releases:

- **CI Workflow**: Runs on every push and pull request
  - Tests with race detection
  - Multi-platform builds (Linux, Windows, macOS)
  - Linting with golangci-lint

- **Release Workflow**: Triggered by version tags
  - Automated multi-platform builds via GoReleaser
  - Automatic changelog generation
  - GitHub release creation with artifacts

### Creating a Release

```bash
# Tag a new version (follows semver)
git tag v1.0.0

# Push the tag to trigger release workflow
git push origin v1.0.0
```

The release workflow will automatically:
1. Build binaries for all platforms
2. Generate changelog from conventional commits
3. Create GitHub release with downloadable assets
4. Generate SHA256 checksums

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

### Adding a New Scanner

1. Create scanner in `internal/infrastructure/scanner/`
2. Implement the `Scanner` interface
3. Register in `cmd/checker/scan.go`
4. Add tests and documentation

### Commit Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/) for changelog generation:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions or modifications
- `chore:` Maintenance tasks

## License

MIT License - see LICENSE file for details.

## Acknowledgments

- Built with [Cobra](https://github.com/spf13/cobra) for CLI
- Logging powered by [Zap](https://github.com/uber-go/zap)
- Color output via [fatih/color](https://github.com/fatih/color)
