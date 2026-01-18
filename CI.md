# Continuous Integration

This project uses GitHub Actions for CI/CD with multiple automated checks:

## Test Workflow

- Runs tests on Ubuntu and macOS with Go 1.21, 1.22, and 1.23
- Executes tests with race detector
- Generates coverage reports (91.8% coverage)
- Uploads coverage to Codecov
- Runs `go vet` and `staticcheck`
- Runs `golangci-lint` for code quality
- Builds binaries for Linux, macOS, and Windows (amd64 and arm64)
- Uploads build artifacts (30-day retention)

## Formatting Workflow

- Checks code formatting with `gofmt`
- Verifies import formatting with `goimports`
- Ensures `go.mod` and `go.sum` are tidy
- Fails if any formatting issues are found

## Commit Lint Workflow

- Validates commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- Checks PR titles match commit message format
- Ensures consistent commit history

## Spellcheck Workflow

- Checks spelling in code, documentation, and comments
- Uses `cspell` with technical term dictionary
- Validates `.go`, `.md`, `.yml`, and `.yaml` files

## SonarQube Workflow

- Performs comprehensive code quality and security analysis
- Uploads coverage reports to SonarCloud
- Analyzes code smells, bugs, vulnerabilities, and security hotspots
- Tracks code quality metrics over time
- Requires `SONAR_TOKEN` secret to be configured in repository settings

## CodeQL Workflow

- GitHub's native security analysis for Go code
- Finds security vulnerabilities and coding errors
- Runs on push, pull requests, and weekly schedule (Mondays)
- Results appear in GitHub Security tab
- Uses both security and quality queries for comprehensive analysis

## DCO Workflow

- Validates Developer Certificate of Origin compliance
- Ensures all commits are signed off with `Signed-off-by` line
- Required for all pull requests
- See [CONTRIBUTING.md](CONTRIBUTING.md) for details on signing commits

## Dependabot

- Automatically checks for dependency updates weekly (every Monday)
- Creates pull requests for:
  - Go module dependencies (go.mod)
  - GitHub Actions versions
- Limits to 5 open PRs at a time to avoid clutter
- PRs are labeled with `dependencies` and ecosystem-specific tags
- Commit messages follow Conventional Commits format (`deps:` for Go modules, `ci:` for Actions)

## GoReleaser Workflow

- Automated release creation when pushing version tags (e.g., `v1.0.0`)
- Builds binaries for multiple platforms:
  - Linux (amd64, arm64)
  - macOS (amd64, arm64)
  - Windows (amd64)
- Builds and publishes multi-arch container images to multiple registries:
  - GitHub Container Registry: `ghcr.io/mmartinv/go-fdo-tool:latest` and `ghcr.io/mmartinv/go-fdo-tool:v1.0.0`
  - Quay.io: `quay.io/mmartinv/go-fdo-tool:latest` and `quay.io/mmartinv/go-fdo-tool:v1.0.0`
  - Both registries support amd64 and arm64 architectures
- Generates checksums and archives
- Creates GitHub releases with automatic changelog from conventional commits
- Groups changes by type (features, fixes, dependencies, etc.)
- Requires `QUAY_USERNAME` and `QUAY_TOKEN` secrets for Quay.io publishing

## Release Drafter

- Automatically maintains draft releases
- Updates draft release on every push to main/master
- Generates changelog from merged PRs
- Categorizes changes by type (features, fixes, documentation, etc.)
- Auto-labels PRs based on branch names and titles
- Suggests next version number based on semver

## PR Auto-Labeler

- Automatically labels PRs based on changed files
- Labels include: `documentation`, `voucher`, `cmd`, `tests`, `ci`, `dependencies`, `examples`, `configuration`
- Helps organize and filter pull requests
- Makes it easier to identify what areas of code are affected

## PR Size Labeler

- Automatically labels PRs by size (XS, S, M, L, XL)
- Helps reviewers prioritize and estimate review time
- Sizes based on lines changed:
  - XS: 0-10 lines
  - S: 11-100 lines
  - M: 101-500 lines
  - L: 501-1000 lines
  - XL: 1000+ lines
- Adds comment on XL PRs suggesting to break them into smaller chunks
- Ignores go.sum, markdown files, and example files in size calculation

## License Checker

- Verifies all dependencies have compatible licenses
- Runs on push, pull requests, and weekly schedule (Sundays)
- Generates license report for all dependencies
- Uploads report as workflow artifact (30-day retention)
- Helps ensure compliance with enterprise requirements

All workflows (except DCO and Release which run only on specific triggers) are triggered on pushes and pull requests to the `main` or `master` branch.

## Workflow Setup Requirements

Most workflows work out of the box, but some require additional configuration:

### SonarQube

- Create a SonarCloud account at https://sonarcloud.io
- Add your repository to SonarCloud
- Add `SONAR_TOKEN` secret to GitHub repository settings
- Update `sonar.projectKey` and `sonar.organization` in `sonar-project.properties`

### Quay.io Publishing

- Create a Quay.io account at https://quay.io
- Create a robot account or generate a personal access token
- Add these secrets to GitHub repository settings:
  - `QUAY_USERNAME`: Your Quay.io username or robot account name
  - `QUAY_TOKEN`: Your Quay.io access token

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on commit message format, code style, and contribution guidelines.
