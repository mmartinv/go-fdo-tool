# Development Guide

## Project Structure

```
go-fdo-tool/
├── .github/
│   ├── workflows/               # GitHub Actions workflows
│   │   ├── test.yml            # Test, lint, build
│   │   ├── formatting.yml      # Code formatting checks
│   │   ├── commitlint.yml      # Commit message validation
│   │   ├── spellcheck.yml      # Spell checking
│   │   ├── sonarqube.yml       # Code quality analysis
│   │   ├── codeql.yml          # Security analysis
│   │   ├── dco.yml             # DCO compliance
│   │   ├── release.yml         # GoReleaser
│   │   ├── release-drafter.yml # Draft releases
│   │   ├── labeler.yml         # Auto-label PRs
│   │   ├── pr-size-labeler.yml # Label PRs by size
│   │   └── license-check.yml   # Dependency licenses
│   ├── dependabot.yml          # Dependency updates
│   ├── labeler.yml             # Labeler configuration
│   └── release-drafter.yml     # Release drafter config
├── .golangci.yml               # Linter configuration
├── .commitlintrc.yml           # Commit lint rules
├── .cspell.json                # Spell check dictionary
├── .goreleaser.yml             # GoReleaser configuration
├── .dockerignore               # Docker build exclusions
├── Containerfile               # Alpine-based container image
├── sonar-project.properties    # SonarQube configuration
├── example/                    # Example vouchers and keys
├── main.go                     # Application entry point
├── cmd/
│   ├── root.go                 # Root command definition
│   ├── voucher.go              # Voucher subcommand implementation
│   ├── credential.go           # Credential subcommand implementation
│   └── keygen.go               # Key generation command
└── pkg/
    ├── voucher/
    │   ├── voucher.go                  # Voucher operations
    │   ├── voucher_test.go             # Core unit tests
    │   └── voucher_additional_test.go  # Additional tests
    ├── credential/
    │   ├── credential.go               # Credential operations
    │   └── credential_test.go          # Credential tests
    └── keygen/
        ├── keygen.go                   # Key generation operations
        └── keygen_test.go              # Key generation tests
```

## Dependencies

This tool uses the official FDO library:
- [github.com/fido-device-onboard/go-fdo](https://github.com/fido-device-onboard/go-fdo) - Official Go implementation of FIDO Device Onboard

## Running Tests

The project includes comprehensive unit tests with **91.8% code coverage** across 134 test cases.

Run all tests:
```bash
go test ./...
```

Run tests with coverage:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

Run tests with race detector:
```bash
go test -race ./...
```

Run specific tests:
```bash
go test -v -run TestExtend ./pkg/voucher/...
```

View coverage by function:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

## Building

Build for your current platform:
```bash
go build -o go-fdo-tool .
```

Cross-compile for different platforms:
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o go-fdo-tool-linux-amd64 .

# macOS
GOOS=darwin GOARCH=arm64 go build -o go-fdo-tool-darwin-arm64 .

# Windows
GOOS=windows GOARCH=amd64 go build -o go-fdo-tool-windows-amd64.exe .
```

## Linting

Run linters:
```bash
go vet ./...
golangci-lint run
```

## Continuous Integration

This project uses GitHub Actions for CI/CD with multiple automated checks including tests, formatting, linting, security analysis, and automated releases. For detailed information about all workflows and setup requirements, see [CI.md](CI.md).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on commit message format, code style, and contribution guidelines.
