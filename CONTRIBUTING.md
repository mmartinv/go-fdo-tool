# Contributing to go-fdo-tool

Thank you for your interest in contributing to go-fdo-tool! This document provides guidelines and instructions for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/go-fdo-tool.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests and checks (see below)
6. Commit your changes (see commit message guidelines)
7. Push to your fork: `git push origin feature/your-feature-name`
8. Create a pull request

## Development Requirements

- Go 1.21 or higher
- `gofmt` and `goimports` for code formatting
- `golangci-lint` for linting (optional but recommended)

## Developer Certificate of Origin (DCO)

This project requires all commits to be signed off, indicating that you agree to the Developer Certificate of Origin (DCO). The DCO is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing.

### Signing Off Commits

To sign off a commit, add the `-s` or `--signoff` flag when committing:

```bash
git commit -s -m "feat: add new feature"
```

This will add a `Signed-off-by` line to your commit message:

```
feat: add new feature

Signed-off-by: Your Name <your.email@example.com>
```

The sign-off must include your real name and email address (no pseudonyms or anonymous contributions).

### Signing Off Existing Commits

If you forgot to sign off commits, you can amend the last commit:

```bash
git commit --amend --signoff
```

For multiple commits, you can use interactive rebase:

```bash
git rebase -i HEAD~N --signoff
```

Replace `N` with the number of commits to sign off.

### DCO Check

All pull requests are automatically checked for DCO compliance. If any commit is missing the sign-off, the DCO check will fail and the PR cannot be merged until all commits are properly signed off.

## Before Submitting

### 1. Run Tests

Ensure all tests pass:

```bash
go test ./...
```

Run tests with race detector:

```bash
go test -race ./...
```

### 2. Check Code Coverage

Verify code coverage is maintained:

```bash
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

The project maintains **91.8% coverage**. Please add tests for new code.

### 3. Format Code

Format your code using `gofmt`:

```bash
gofmt -w .
```

Format imports using `goimports`:

```bash
goimports -w .
```

### 4. Tidy Dependencies

Ensure go.mod and go.sum are tidy:

```bash
go mod tidy
```

### 5. Run Linters

Run the linter to catch common issues:

```bash
golangci-lint run
```

Or use `go vet`:

```bash
go vet ./...
```

### 6. Check Spelling

If you've modified documentation or added comments, check spelling:

```bash
npm install -g cspell
cspell "**/*.{go,md,yml,yaml}"
```

Technical terms are defined in `.cspell.json`.

## Commit Message Guidelines

This project follows the [Conventional Commits](https://www.conventionalcommits.org/) specification.

### Commit Message Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- **feat**: A new feature
- **fix**: A bug fix
- **docs**: Documentation only changes
- **style**: Changes that don't affect the meaning of the code (white-space, formatting, etc.)
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**: A code change that improves performance
- **test**: Adding missing tests or correcting existing tests
- **build**: Changes that affect the build system or external dependencies
- **ci**: Changes to CI configuration files and scripts
- **deps**: Dependency updates (typically used by Dependabot)
- **chore**: Other changes that don't modify src or test files
- **revert**: Reverts a previous commit

### Examples

Good commit messages:

```
feat: add support for RSA 4096 keys
fix: handle invalid PEM data gracefully
docs: update installation instructions
test: add tests for DER key loading
ci: add spellcheck workflow
deps: bump github.com/fido-device-onboard/go-fdo from 0.0.1 to 0.0.2
```

Bad commit messages:

```
Update code
Fixed bug
WIP
asdf
```

### Scopes (Optional)

You can optionally add a scope to provide additional context:

```
feat(voucher): add JSON output support
fix(cmd): correct error message formatting
docs(readme): add coverage badge
test(voucher): increase coverage to 92%
```

Valid scopes: `voucher`, `cmd`, `ci`, `deps`, `docs`, `workflow`

### Rules

- Use the imperative mood in the subject line ("add" not "added" or "adds")
- Don't capitalize the first letter of the subject line
- No period at the end of the subject line
- Limit the subject line to 100 characters
- Separate subject from body with a blank line
- Wrap the body at 72 characters
- Use the body to explain what and why vs. how

## Pull Request Guidelines

### PR Title

The PR title should follow the same format as commit messages:

```
feat: add support for certificate chains
fix: resolve key type mismatch error
```

### PR Description

Include in your PR description:

1. **What**: What does this PR do?
2. **Why**: Why is this change necessary?
3. **How**: How does it work? (if not obvious)
4. **Testing**: How was it tested?
5. **Related Issues**: Link to any related issues

Example:

```markdown
## What
Adds support for loading RSA 4096 bit keys in addition to existing RSA 2048 support.

## Why
Users with RSA 4096 keys were unable to extend vouchers, limiting adoption.

## How
Updated the key loading logic to detect key size and use appropriate hash algorithm.

## Testing
- Added unit tests for RSA 4096 key loading
- Tested with real-world vouchers
- All existing tests pass

## Related Issues
Fixes #123
```

## Code Style

### Go Code

- Follow standard Go conventions
- Use `gofmt` for formatting
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions small and focused
- Avoid global variables

### Comments

- Write comments for exported functions, types, and constants
- Use complete sentences with proper punctuation
- Explain *why*, not *what* (the code shows what)

Example:

```go
// LoadFromFile loads an ownership voucher from a PEM-encoded file.
// It supports both PEM-encoded vouchers as specified in the FDO standard
// and returns an error if the file format is invalid.
func LoadFromFile(path string) (*fdo.Voucher, error) {
    // Implementation
}
```

### Error Messages

- Use lowercase for error messages
- Don't end with punctuation
- Use `fmt.Errorf` with `%w` for error wrapping
- Provide context in error messages

Example:

```go
return nil, fmt.Errorf("failed to load voucher: %w", err)
```

## Testing Guidelines

### Writing Tests

- Test files should be named `*_test.go`
- Test function names should start with `Test`
- Use table-driven tests when testing multiple cases
- Include both positive and negative test cases
- Test error paths as well as success paths

Example:

```go
func TestLoadFromFile(t *testing.T) {
    tests := []struct {
        name    string
        file    string
        wantErr bool
    }{
        {
            name:    "valid voucher",
            file:    "testdata/valid.pem",
            wantErr: false,
        },
        {
            name:    "invalid file",
            file:    "nonexistent.pem",
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := LoadFromFile(tt.file)
            if (err != nil) != tt.wantErr {
                t.Errorf("LoadFromFile() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

### Test Coverage

- Aim for high test coverage (90%+)
- Focus on testing critical paths and error handling
- Don't test third-party libraries
- Test edge cases and boundary conditions

## Continuous Integration

All pull requests are automatically checked for:

- ✅ **Tests**: All tests must pass
- ✅ **Code Coverage**: Coverage reports are generated
- ✅ **Formatting**: Code must be properly formatted with `gofmt` and `goimports`
- ✅ **Linting**: Code must pass `golangci-lint` and `staticcheck`
- ✅ **Spelling**: Documentation and comments must pass spellcheck
- ✅ **Commit Messages**: Commits must follow Conventional Commits format
- ✅ **Build**: Code must build successfully for all platforms
- ✅ **SonarQube**: Code quality and security analysis must pass
- ✅ **CodeQL**: GitHub security analysis must pass
- ✅ **DCO**: All commits must be signed off
- ✅ **License Check**: All dependencies must have compatible licenses
- 🏷️ **Auto-labeling**: PRs are automatically labeled by changed files and size

If any check fails, the PR cannot be merged. Fix the issues and push again.

## Dependabot

This project uses Dependabot to automatically keep dependencies up to date. Dependabot will:

- Check for updates to Go modules and GitHub Actions weekly
- Create pull requests for dependency updates
- Follow the project's commit message format (`deps:` prefix for Go modules, `ci:` for Actions)
- Automatically assign reviewers and apply appropriate labels

When reviewing Dependabot PRs:

1. Check that all CI checks pass
2. Review the changelog/release notes for breaking changes
3. Test locally if the update involves major version changes
4. Merge if everything looks good

You don't need to manually update dependencies in most cases - Dependabot will handle it automatically.

## Creating Releases

This project uses automated releases with GoReleaser. To create a new release:

1. **Ensure main branch is ready:**
   - All tests pass
   - Changelog is up to date (Release Drafter creates drafts automatically)
   - Version number follows [Semantic Versioning](https://semver.org/)

2. **Create and push a version tag:**
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0"
   git push origin v1.0.0
   ```

3. **Automated release process:**
   - GoReleaser workflow triggers automatically
   - Builds binaries for Linux, macOS, and Windows (amd64 and arm64)
   - Builds and publishes multi-arch container images to multiple registries:
     - GitHub Container Registry: `ghcr.io/mmartinv/go-fdo-tool:latest` and `ghcr.io/mmartinv/go-fdo-tool:v1.0.0`
     - Quay.io: `quay.io/mmartinv/go-fdo-tool:latest` and `quay.io/mmartinv/go-fdo-tool:v1.0.0`
     - Both include amd64 and arm64 images
   - Creates checksums and archives
   - Generates changelog from conventional commits
   - Publishes GitHub release with all artifacts

**Note**: To publish to Quay.io, you need to set up the following repository secrets:
- `QUAY_USERNAME`: Your Quay.io username
- `QUAY_TOKEN`: A Quay.io robot account token or personal access token

To create these secrets:
1. Go to your GitHub repository → Settings → Secrets and variables → Actions
2. Click "New repository secret"
3. Add `QUAY_USERNAME` and `QUAY_TOKEN` with your Quay.io credentials

4. **Version numbering:**
   - Major version (v2.0.0): Breaking changes
   - Minor version (v1.1.0): New features, backward compatible
   - Patch version (v1.0.1): Bug fixes, backward compatible

The Release Drafter maintains a draft release that's automatically updated with each merge to main. You can review and edit this draft before creating the actual release tag.

## Questions?

If you have questions or need help, please:

1. Check existing issues and pull requests
2. Read the documentation in the README
3. Open a new issue with your question

## Code of Conduct

Be respectful and professional in all interactions. We aim to maintain a welcoming and inclusive community.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
