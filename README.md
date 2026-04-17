# az-port

`az-port` is a Go CLI for developers who need to understand port usage quickly, detect real conflicts, and prevent startup failures before they happen.

It is designed for local development workflows:
- inspect listening ports
- find which process owns a port
- distinguish real conflicts from normal dual-stack/shared-process usage
- preflight-check required ports before starting an app
- suggest free ports in a preferred development range

## Features

- Developer-focused `list` output with listening ports by default
- `find` to inspect a specific port or multiple ports
- `conflicts` to report real conflicts only
- `check` to validate required ports before startup
- `suggest` to recommend currently available ports
- Structured JSON output with `--report-json`
- Local-first metrics logging with `--metrics-local`
- Project-level defaults via `az-port.yaml`
- Cross-platform support: Windows, Linux, macOS

## Installation

`az-port` is intended to be installed as a global CLI so you can run it from any directory:

```bash
az-port list
az-port check
az-port suggest
```

### Recommended: GitHub Releases

```bash
# Download the latest platform archive from GitHub Releases,
# extract the binary, and place it on your PATH.
```

Download the latest release from [GitHub Releases](https://github.com/ErdemSusam23/az-port/releases).
Detailed setup steps for Windows, Linux, and macOS are in [docs/INSTALL.md](docs/INSTALL.md).

### From Source

```bash
# Install directly into your Go bin directory
go install github.com/ErdemSusam23/az-port@latest
```

You can also build it manually:

```bash
git clone https://github.com/ErdemSusam23/az-port.git
cd az-port
go build -o az-port
```

## Usage

### List Ports

```bash
# List developer-relevant listening ports (default)
az-port list

# Show all connection states
az-port list --all-states

# Filter by protocol
az-port list --tcp
az-port list --udp

# Filter by range, process name, or PID
az-port list --port 3000-4000
az-port list --name node
az-port list --pid 1234

# Output raw data
az-port list --format json
az-port list --format csv
```

### Find Port Ownership

```bash
# Find what is using port 3000
az-port find 3000

# Find multiple ports
az-port find 3000 5432 6379
az-port find 8080,8081,3000

# Structured output
az-port find 3000 --report-json
```

### Detect Real Conflicts

```bash
# Show system-wide real conflicts
az-port conflicts

# Check a single port
az-port conflicts --port 3000

# Structured output
az-port conflicts --report-json
```

### Preflight Required Ports

```bash
# Check explicit ports before app startup
az-port check 3000
az-port check 3000 5432 6379

# Use expected_ports from az-port.yaml
az-port check
```

`check` returns a non-zero exit code when a requested port is not available for startup.

### Suggest Free Ports

```bash
# Suggest free ports from the default range
az-port suggest

# Suggest from a custom range
az-port suggest --range 3000-3999

# Suggest multiple ports
az-port suggest --range 3000-3999 --count 5
```

## Global Flags

All major commands support these global flags:

```bash
# Use a project config explicitly
az-port --config ./az-port.yaml check

# Emit a structured machine-readable report
az-port find 5432 --report-json

# Append local JSONL metrics for later inspection
az-port check 3000 --metrics-local .az-port/metrics.jsonl
```

## Project Config

`az-port` can discover `az-port.yaml` or `az-port.yml` by walking up from the current working directory.

Example:

```yaml
expected_ports:
  - 3000
  - 5432
critical_ports:
  - 3000
ignore_ports:
  - 5353
suggest_range: 3000-3999
suggest_count: 5
```

Current supported keys:
- `expected_ports`
- `critical_ports`
- `ignore_ports`
- `suggest_range`
- `suggest_count`

## Examples

### Inspect a Port Used by a Local Service

```bash
$ az-port find 5432

Port 5432:
  In use by postgres.exe (PID: 6280)
  No real conflict
  Addresses: 0.0.0.0:5432, [::]:5432
```

### Preflight Check Before Startup

```bash
$ az-port check 3000 5432

1 available, 1 shared_process
- Port 3000: available (Port 3000 is available)
- Port 5432: shared_process (Port 5432 is used by the same process on multiple addresses)
  postgres.exe (PID: 6280) [0.0.0.0:5432, [::]:5432]
Recommendation: Try available port(s): 3001, 3002, 3003
```

### Structured JSON Report

```bash
$ az-port find 5432 --report-json
{
  "command": "find",
  "summary": "1 shared_process",
  "findings": [
    {
      "port": 5432,
      "status": "shared_process",
      "risk_level": "LOW",
      "message": "Port 5432 is used by the same process on multiple addresses"
    }
  ],
  "metrics": {
    "duration_ms": 716,
    "entries_scanned": 145,
    "findings_count": 1,
    "process_resolution_rate": 1
  }
}
```

## Development

### Build

```bash
# Windows
go build -o az-port.exe

# Linux
GOOS=linux GOARCH=amd64 go build -o az-port

# macOS
GOOS=darwin GOARCH=amd64 go build -o az-port
GOOS=darwin GOARCH=arm64 go build -o az-port-macos
```

### Run Tests

```bash
go test ./...
```

### Release Artifacts

GitHub Actions builds tagged releases for:

- Windows x86_64
- Linux x86_64
- macOS x86_64
- macOS arm64

Each release publishes packaged binaries plus `checksums.txt`.

## Project Structure

```text
az-port/
├── cmd/                 # CLI commands and report builders
├── internal/
│   ├── analyzer/        # Conflict detection logic
│   ├── config/          # az-port.yaml parsing and discovery
│   ├── formatter/       # Table, JSON, CSV formatting
│   ├── metrics/         # Local-first JSONL metrics logging
│   ├── models/          # Shared data and report models
│   └── scanner/         # Platform-specific port scanners
├── main.go              # Entry point
└── go.mod               # Go module definition
```

## Dependencies

- [spf13/cobra](https://github.com/spf13/cobra) - CLI framework
- [fatih/color](https://github.com/fatih/color) - Colored terminal output
- [olekukonko/tablewriter](https://github.com/olekukonko/tablewriter) - Table formatting

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome. Open an issue or submit a pull request.

## Author

[Erdem Susam](https://github.com/ErdemSusam23)
