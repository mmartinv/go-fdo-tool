# go-fdo-tool

A command line tool for managing FIDO Device Onboard (FDO) ownership vouchers, written in Go using the Cobra CLI framework and the official [go-fdo](https://github.com/fido-device-onboard/go-fdo) library.

## Overview

FDO (FIDO Device Onboard) is a protocol for securely onboarding IoT devices. Ownership vouchers are cryptographic documents that represent device ownership and can be transferred between owners. This tool provides utilities to inspect and extend ownership vouchers.

## Features

- **Human-friendly output**: Display voucher information in easy-to-read text format by default
- **JSON output**: Optional JSON format for scripting and programmatic processing
- **Complete voucher details**: Shows all voucher components including manufacturer key, HMAC, certificate chains, and ownership entries
- **Ownership transfer**: Extend vouchers by cryptographically signing ownership transfers to new owners
- **Voucher verification**: Comprehensive cryptographic verification with multiple levels (basic, full with secrets, trusted roots)
- **Credential management**: Print and inspect device credentials with secure secret handling
- **Key generation**: Generate FDO-compliant manufacturer and owner private keys
- **Key format support**: Supports ECDSA (P-256, P-384) and RSA (2048, 3072, 4096) keys in both PEM and DER formats
  - **Note**: All keys in a voucher chain must use the same type and size as the manufacturer's key
- **Certificate support**: Supports public keys, X.509 certificates, and certificate chains
- **PEM format support**: Read and write vouchers in PEM-encoded format
- **CBOR encoding**: Uses CBOR (RFC 8949) as specified by the FDO standard
- **Official library integration**: Built on the official go-fdo library

## Installation

### Prerequisites

- Go 1.21 or higher

### Build from source

```bash
git clone https://github.com/mmartinv/go-fdo-tool.git
cd go-fdo-tool
go build -o go-fdo-tool .
```

The compiled binary will be created as `go-fdo-tool` in the current directory.

### Download Pre-built Binaries

Pre-built binaries are available for each release on the [GitHub Releases](https://github.com/mmartinv/go-fdo-tool/releases) page.

Download the appropriate binary for your platform:

```bash
# Example for Linux amd64
wget https://github.com/mmartinv/go-fdo-tool/releases/download/v1.0.0/go-fdo-tool_1.0.0_linux_amd64.tar.gz
tar -xzf go-fdo-tool_1.0.0_linux_amd64.tar.gz
chmod +x go-fdo-tool
./go-fdo-tool --help
```

Verify the download with checksums:

```bash
sha256sum -c checksums.txt
```

### Using Container Images

Container images are automatically published to both GitHub Container Registry and Quay.io with each release. Images are available for both amd64 and arm64 architectures.

#### Pull the image

From GitHub Container Registry:

```bash
# Pull latest version
docker pull ghcr.io/mmartinv/go-fdo-tool:latest

# Pull specific version
docker pull ghcr.io/mmartinv/go-fdo-tool:v1.0.0
```

From Quay.io:

```bash
# Pull latest version
docker pull quay.io/mmartinv/go-fdo-tool:latest

# Pull specific version
docker pull quay.io/mmartinv/go-fdo-tool:v1.0.0
```

Or using Podman:

```bash
# From GHCR
podman pull ghcr.io/mmartinv/go-fdo-tool:latest

# From Quay.io
podman pull quay.io/mmartinv/go-fdo-tool:latest
```

#### Run the container

```bash
# Show help
docker run --rm ghcr.io/mmartinv/go-fdo-tool:latest --help

# Print a voucher (mount the directory containing the voucher file)
docker run --rm -v $(pwd):/app/vouchers ghcr.io/mmartinv/go-fdo-tool:latest \
  voucher print /app/vouchers/voucher.pem

# Extend a voucher
docker run --rm -v $(pwd):/app/vouchers ghcr.io/mmartinv/go-fdo-tool:latest \
  voucher extend /app/vouchers/voucher.pem \
  /app/vouchers/owner_key.pem \
  /app/vouchers/new_owner_cert.pem \
  -o /app/vouchers/extended.pem
```

With Podman:

```bash
podman run --rm -v $(pwd):/app/vouchers:Z ghcr.io/mmartinv/go-fdo-tool:latest \
  voucher print /app/vouchers/voucher.pem
```

#### Build your own image

You can also build the container image locally:

```bash
# Using Docker
docker build -f Containerfile -t go-fdo-tool .

# Using Podman
podman build -f Containerfile -t go-fdo-tool .

# Using Buildah
buildah bud -f Containerfile -t go-fdo-tool .
```

The container runs as a non-root user (UID 1000) for security.

## Usage

### Basic Command Structure

```bash
# Voucher operations
go-fdo-tool voucher <command> [arguments] [flags]

# Credential operations
go-fdo-tool credential <command> [arguments] [flags]

# Key generation
go-fdo-tool keygen [flags]
```

### Available Commands

#### Print Voucher Information

Display the contents of an ownership voucher in a human-readable text format (default) or JSON format (with `--json` flag).

```bash
go-fdo-tool voucher print <voucher-file> [--json]
```

**Example (Default Text Output):**

```bash
$ go-fdo-tool voucher print sample-voucher.pem
```

**Output:**

```
OWNERSHIP VOUCHER
=================

Protocol Version: 1.1
GUID: 66b2146ffec53ca6ad017625990572ce
Device Info: go.fdo.example

Manufacturer Public Key:
  Type: ECDSA secp384r1 = NIST-P-384
  -----BEGIN PUBLIC KEY-----
  WHgwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQcJH/SAC7/pkTXf4cKsJtVmIuLuEcK
  nLEB1BVwCE4eRZawgsxOs5/SRbk5yW4Mz/cV9gvYMtBlPodlvc2RKqfuWanCuFzP
  OPsoiqcfTNJQQc5UKY5PVRn1dni+m2bt0QI=
  -----END PUBLIC KEY-----

Header HMAC:
  Algorithm: HmacSha384Hash
  Value: 48e2879f168dd012f237ec2ffd2c21fa87c5684218836f247a24e2dd74882ed8405bcd4cd9823b36e23d996c7e0a30a9

Device Certificate Chain Hash:
  Algorithm: Sha384Hash
  Value: 32b2b9b1e5935c2af4ff6c14052a7dd22d296090f5650b5befcf031dca4a51c6db419522d49f82c1de4cc07aa49212bb

Rendezvous Information:
  Directive 1:
    IPAddress: 192.168.122.1
    DevPort: 8082
    OwnerPort: 8082
    Protocol: HTTP
  Directive 2:
    DNS: ofdo.example.com
    DevPort: 8082
    OwnerPort: 8082
    Protocol: HTTP

Device Certificate Chain (2 certificates):
  Certificate 1:
    Subject: CN=go.fdo.example
    Issuer: CN=dev.ca.fdo
    Valid From: 2024-01-13 19:22:04 UTC
    Valid Until: 2034-01-10 19:22:04 UTC
    Serial Number: 6127028952862471157
  Certificate 2:
    Subject: CN=dev.ca.fdo
    Issuer: CN=dev.ca.fdo
    Valid From: 2024-01-13 19:22:04 UTC
    Valid Until: 2034-01-10 19:22:04 UTC
    Serial Number: 407768008402999189559304806578013625293084135153

Ownership Entries: None (manufacturer voucher)
```

**Example (JSON Output):**

```bash
$ go-fdo-tool voucher print sample-voucher.pem --json
```

**Output:**

```json
{
  "deviceCertificateChain": [
    {
      "issuer": "CN=dev.ca.fdo",
      "notAfter": "2034-01-10 19:22:04 UTC",
      "notBefore": "2024-01-13 19:22:04 UTC",
      "serialNumber": "6127028952862471157",
      "subject": "CN=go.fdo.example"
    }
  ],
  "entries": [],
  "header": {
    "devCertChainHash": {
      "algorithm": "Sha384Hash",
      "value": "0x32b2b9b1e5935c2af4ff6c14052a7dd22d296090f5650b5befcf031dca4a51c6db419522d49f82c1de4cc07aa49212bb"
    },
    "deviceInfo": "go.fdo.example",
    "guid": "66b2146ffec53ca6ad017625990572ce",
    "manufacturerKey": {
      "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "type": "ECDSA secp384r1 = NIST-P-384"
    },
    "rvInfo": [
      [
        {
          "IPAddress": "192.168.122.1"
        },
        {
          "DevPort": 8082
        },
        {
          "OwnerPort": 8082
        },
        {
          "Protocol": "HTTP"
        }
      ]
    ],
    "version": "1.1"
  },
  "headerHmac": {
    "algorithm": "HmacSha384Hash",
    "value": "0x48e2879f168dd012f237ec2ffd2c21fa87c5684218836f247a24e2dd74882ed8405bcd4cd9823b36e23d996c7e0a30a9"
  },
  "version": "1.1"
}
```

#### Extend Ownership Voucher

Extend an ownership voucher by transferring ownership to a new owner. This creates a cryptographically signed ownership entry in the voucher chain.

```bash
go-fdo-tool voucher extend <voucher-file> <owner-private-key> <new-owner-public-key-or-cert> [--output <file>]
```

**Arguments:**
- `voucher-file`: Path to the ownership voucher to extend
- `owner-private-key`: Private key of the current owner (PEM or DER format)
  - For a manufacturer voucher (no entries), this is the manufacturer's private key
  - For an extended voucher, this is the last owner's private key
  - Supports EC PRIVATE KEY, PRIVATE KEY (PKCS#8), and RSA PRIVATE KEY formats
  - Supports both PEM-encoded and raw DER-encoded keys
- `new-owner-public-key-or-cert`: New owner's public key or certificate (PEM format)
  - Can be a public key file
  - Can be a certificate file
  - Can be a certificate chain (multiple PEM certificates)
  - **IMPORTANT**: Must be the same key type and size as the manufacturer's key
    - If manufacturer uses ECDSA P-384, all owners must use ECDSA P-384
    - If manufacturer uses ECDSA P-256, all owners must use ECDSA P-256
    - If manufacturer uses RSA 2048, all owners must use RSA 2048
    - If manufacturer uses RSA 3072, all owners must use RSA 3072
    - Mixed key types are not supported in the ownership chain

**Flags:**
- `-o, --output <file>`: Save extended voucher to file instead of stdout

**Example (Output to stdout):**

```bash
./go-fdo-tool voucher extend example/voucher.pem example/owner_key.pem example/new_owner_cert.pem
```

This outputs the extended voucher in PEM format to stdout, which can be redirected:

```bash
./go-fdo-tool voucher extend example/voucher.pem example/owner_key.pem example/new_owner_cert.pem > extended.pem
```

**Example (Save to file):**

```bash
./go-fdo-tool voucher extend example/voucher.pem example/owner_key.pem example/new_owner_cert.pem -o extended.pem
```

**Example (Using DER format key):**

```bash
./go-fdo-tool voucher extend example/voucher.pem example/owner_key.der example/new_owner_cert.pem -o extended.pem
```

**Key Type Mismatch Error:**

If you try to extend a voucher with a different key type than the manufacturer's key, you'll get an error:

```bash
# This will fail if the voucher uses P-384 but you provide a P-256 certificate
./go-fdo-tool voucher extend example/voucher.pem example/owner_key.pem wrong_key_type.pem
```

Error:
```
Error: failed to extend voucher: owner key for voucher extension did not match the type and size/curve of the manufacturer key
```

To check the manufacturer's key type, use the print command:
```bash
./go-fdo-tool voucher print example/voucher.pem | grep "Manufacturer Public Key" -A 1
```

**Verify Extended Voucher:**

After extending, you can print the voucher to verify the ownership transfer:

```bash
./go-fdo-tool voucher print extended.pem | tail -20
```

Output will show:
```
Ownership Entries (1 transfers):
  Entry 1:
    Previous Hash: 5b0527b7158dce7ca6dd6a96aec60e1df1cfcfd2229eb45bb5c734990d944d8b
    Header Hash: 0e7ae1b63aaa49cd6fc4b85c946fdbe7127951c6455a5456a851593e9c6c0940
    Owner Public Key Type: ECDSA secp384r1 = NIST-P-384
    -----BEGIN PUBLIC KEY-----
    ...
    -----END PUBLIC KEY-----
```

**Chaining Multiple Transfers:**

To transfer ownership multiple times, use the previous owner's key each time:

```bash
# First transfer (manufacturer to owner1)
./go-fdo-tool voucher extend voucher.pem manufacturer_key.pem owner1_cert.pem -o voucher_owner1.pem

# Second transfer (owner1 to owner2)
./go-fdo-tool voucher extend voucher_owner1.pem owner1_key.pem owner2_cert.pem -o voucher_owner2.pem

# Verify the chain
./go-fdo-tool voucher print voucher_owner2.pem
```

The voucher will show:
```
Ownership Entries (2 transfers):
  Entry 1:
    ...
  Entry 2:
    ...
```

#### Verify Ownership Voucher

Verify the cryptographic integrity of an ownership voucher. The verification process checks multiple aspects of the voucher depending on what secrets are provided.

```bash
go-fdo-tool voucher verify <voucher-file> [flags]
```

**Verification Levels:**

1. **Basic Verification (No Secrets Required)**:
   - Ownership chain signatures (VerifyEntries)
   - Certificate chain hash integrity (VerifyCertChainHash)
   - Device certificate chain validation (self-signed trust)
   - Manufacturer certificate chain validation (self-signed trust)

2. **Full Verification (With Device Credential)**:
   - All basic checks, plus:
   - Header HMAC verification using device credential's HMAC secret
   - Manufacturer public key hash verification

3. **Trusted Roots Verification (Optional)**:
   - Certificate chain validation against trusted CA roots

**Flags:**
- `--credential <file>` - Device credential file for full verification (CBOR format)
- `--hmac-secret <hex>` - HMAC secret as hex string (alternative to --credential)
- `--hmac-secret-file <file>` - File containing HMAC secret (hex or binary)
- `--public-key-hash <hex>` - Public key hash as hex string (alternative to --credential)
- `--public-key-hash-file <file>` - File containing public key hash
- `--ca-certs <file>` - CA certificate bundle for trusted chain verification
- `--json` - Output results in JSON format

**Exit Codes:**
- `0` - All verification checks passed
- `1` - One or more verification checks failed
- `2` - Usage/argument errors

**Example (Basic Verification):**

```bash
./go-fdo-tool voucher verify example/voucher.pem
```

**Output:**
```
VERIFICATION RESULT: PASSED
============================

✓ Ownership Entries: Valid
✓ Certificate Chain Hash: Valid
✓ Device Certificate Chain: Valid (self-signed)
✓ Manufacturer Certificate Chain: Valid (self-signed)

All checks passed.
```

**Example (Full Verification with Device Credential):**

```bash
./go-fdo-tool voucher verify example/voucher.pem --credential device_cred.cbor
```

**Example (JSON Output):**

```bash
./go-fdo-tool voucher verify example/voucher.pem --json
```

**Output:**
```json
{
  "passed": true,
  "checks": [
    {
      "name": "Ownership Entries",
      "passed": true,
      "error": null
    },
    {
      "name": "Certificate Chain Hash",
      "passed": true,
      "error": null
    }
  ],
  "summary": {
    "total": 4,
    "passed": 4,
    "failed": 0
  }
}
```

**Example (Use in CI/CD):**

```bash
# Verify voucher and fail pipeline if invalid
./go-fdo-tool voucher verify voucher.pem || exit 1
```

#### Print Device Credential

Display the contents of a device credential file in human-readable text format (default) or JSON format.

```bash
go-fdo-tool credential print <credential-file> [flags]
```

**Flags:**
- `--json` - Output in JSON format
- `--show-secrets` - Display full private key and HMAC secret (hidden by default)

**Example (Default Output - Secrets Hidden):**

```bash
./go-fdo-tool credential print device_credential.cbor
```

**Output:**
```
DEVICE CREDENTIAL
=================

Active: true
Protocol Version: 1.1
Device Info: Device description

Public Key:
  Type: ECDSA secp384r1 = NIST-P-384
  -----BEGIN PUBLIC KEY-----
  ...
  -----END PUBLIC KEY-----

Private Key Info:
  Type: ECDSA
  Curve: P-384
  Bits: 384
  [Use --show-secrets to display the full private key]

HMAC Secret:
  [Use --show-secrets to display the HMAC secret]
  Hint: Secret is 48 bytes long
```

**Example (Show Secrets):**

```bash
./go-fdo-tool credential print device_credential.cbor --show-secrets
```

**Example (JSON Output):**

```bash
./go-fdo-tool credential print device_credential.cbor --json
```

#### Generate Keys

Generate FDO-compliant private keys for use as manufacturer or owner keys.

```bash
go-fdo-tool keygen [flags]
```

**Supported Key Types:**
- `ecdsa-p256` - ECDSA with NIST P-256 curve (secp256r1, prime256v1)
- `ecdsa-p384` - ECDSA with NIST P-384 curve (secp384r1) - **Recommended for FDO**
- `rsa-2048` - RSA with 2048-bit key
- `rsa-3072` - RSA with 3072-bit key
- `rsa-4096` - RSA with 4096-bit key

**Flags:**
- `-t, --type <type>` - Key type (default: ecdsa-p384)
- `-f, --format <format>` - Output format: pem or der (default: pem)
- `--private-key <file>` - Output file for private key (stdout if not specified)
- `--public-key <file>` - Optional output file for public key
- `--list` - List all supported key types in JSON format

**Example (Generate ECDSA P-384 Key - Recommended):**

```bash
./go-fdo-tool keygen --type ecdsa-p384 --private-key owner_key.pem --public-key owner_pub.pem
```

**Output:**
```
Generating ecdsa-p384 key...
Generated ECDSA key (384 bits)
Curve: P-384
Private key saved to: owner_key.pem
Public key saved to: owner_pub.pem
```

**Example (List Supported Key Types):**

```bash
./go-fdo-tool keygen --list
```

**Output:**
```json
{
  "supportedKeyTypes": [
    {
      "name": "ecdsa-p256",
      "description": "ECDSA with NIST P-256 curve (256-bit)",
      "aliases": ["secp256r1", "p256", "prime256v1"]
    },
    {
      "name": "ecdsa-p384",
      "description": "ECDSA with NIST P-384 curve (384-bit)",
      "aliases": ["secp384r1", "p384"],
      "recommended": true
    },
    {
      "name": "rsa-2048",
      "description": "RSA with 2048-bit key",
      "aliases": ["rsa2048", "2048"]
    }
  ]
}
```

**Example (Generate RSA Key in DER Format):**

```bash
./go-fdo-tool keygen --type rsa-2048 --format der --private-key key.der
```

**Example (Generate Key to Stdout for Piping):**

```bash
./go-fdo-tool keygen --type ecdsa-p384 > owner_key.pem
```

**Security Notes:**
- Private keys are saved with restrictive permissions (0600 - owner read/write only)
- Keys are generated in PKCS#8 format
- Use ecdsa-p384 for best balance of security and performance in FDO

### Help Commands

Get general help:

```bash
go-fdo-tool --help
```

Get help for specific commands:

```bash
# Voucher commands
go-fdo-tool voucher --help

# Credential commands
go-fdo-tool credential --help

# Key generation
go-fdo-tool keygen --help
```

Get help for a specific subcommand:

```bash
go-fdo-tool voucher print --help
go-fdo-tool voucher verify --help
go-fdo-tool credential print --help
```

## Ownership Voucher Format

Ownership vouchers are stored in PEM format with CBOR-encoded data:

```
-----BEGIN OWNERSHIP VOUCHER-----
<base64-encoded CBOR data>
-----END OWNERSHIP VOUCHER-----
```

### Structure

The voucher structure follows the FDO specification and includes:

- **version**: FDO protocol version (displayed as major.minor, e.g., "1.1")
- **header**: Voucher header containing:
  - **version**: Header version number
  - **guid**: Globally unique identifier for the device (16 bytes)
  - **deviceInfo**: Human-readable device information string
  - **rvInfo**: Rendezvous instructions for device onboarding
  - **manufacturerKey**: The manufacturer's public key (displayed in PEM format)
  - **devCertChainHash**: Hash of the device certificate chain (optional)
- **headerHmac**: HMAC over the header
- **deviceCertificateChain**: Device certificate chain with details (subject, issuer, validity period, serial number)
- **entries**: Array of ownership voucher entries (one per ownership transfer)

### Data Encoding

- **PEM**: Standard PEM encoding as defined in RFC 7468
- **CBOR**: Concise Binary Object Representation as defined in RFC 8949
- **COSE**: CBOR Object Signing and Encryption for cryptographic operations

## Example Workflow

The `example/` directory contains sample files for testing:
- `voucher.pem` - Manufacturer voucher (no ownership entries, uses ECDSA P-384)
- `owner_key.pem` - Current owner's private key in PEM format (manufacturer key, ECDSA P-384)
- `owner_key.der` - Current owner's private key in DER format (same key as above, ECDSA P-384)
- `new_owner_cert.pem` - New owner's certificate (ECDSA P-384, matches manufacturer key type)
- `new_owner_key.pem` - New owner's private key (ECDSA P-384, for subsequent transfers)

**Note:** All keys in the example directory use ECDSA P-384 because the manufacturer key in the voucher is ECDSA P-384. When extending vouchers, the new owner's key type must always match the manufacturer's key type.

1. **Inspect a manufacturer voucher (default text format):**
   ```bash
   ./go-fdo-tool voucher print example/voucher.pem
   ```

2. **Transfer ownership (extend the voucher):**
   ```bash
   ./go-fdo-tool voucher extend example/voucher.pem example/owner_key.pem example/new_owner_cert.pem -o example/extended.pem
   ```

3. **View the extended voucher to verify ownership transfer:**
   ```bash
   ./go-fdo-tool voucher print example/extended.pem
   ```

   The extended voucher will show the ownership entry:
   ```
   Ownership Entries (1 transfers):
     Entry 1:
       Previous Hash: ...
       Header Hash: ...
       Owner Public Key Type: ECDSA secp384r1 = NIST-P-384
       -----BEGIN PUBLIC KEY-----
       ...
       -----END PUBLIC KEY-----
   ```

4. **Export voucher information as JSON for scripting:**
   ```bash
   ./go-fdo-tool voucher print example/voucher.pem --json > voucher.json
   ```

5. **Verify the voucher:**
   ```bash
   # Basic verification (no secrets required)
   ./go-fdo-tool voucher verify example/voucher.pem

   # Verify and check exit code
   ./go-fdo-tool voucher verify example/voucher.pem && echo "Valid" || echo "Invalid"
   ```

6. **Generate new owner keys:**
   ```bash
   # Generate ECDSA P-384 key pair (recommended)
   ./go-fdo-tool keygen --type ecdsa-p384 --private-key new_owner.pem --public-key new_owner_pub.pem

   # List all supported key types
   ./go-fdo-tool keygen --list
   ```

7. **Chain multiple ownership transfers:**
   ```bash
   # Extend to second owner (requires new_owner_key.pem and second_owner_cert.pem)
   ./go-fdo-tool voucher extend example/extended.pem example/new_owner_key.pem second_owner_cert.pem -o example/extended2.pem

   # View complete ownership chain
   ./go-fdo-tool voucher print example/extended2.pem

   # Verify the extended voucher
   ./go-fdo-tool voucher verify example/extended2.pem
   ```

8. **View device credential (if available):**
   ```bash
   # Print device credential (secrets hidden by default)
   ./go-fdo-tool credential print device_credential.cbor

   # Show full credential including secrets
   ./go-fdo-tool credential print device_credential.cbor --show-secrets
   ```

## Development

### Project Structure

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

### Dependencies

This tool uses the official FDO library:
- [github.com/fido-device-onboard/go-fdo](https://github.com/fido-device-onboard/go-fdo) - Official Go implementation of FIDO Device Onboard

### Running Tests

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

### Building

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

### Linting

Run linters:
```bash
go vet ./...
golangci-lint run
```

### Continuous Integration

This project uses GitHub Actions for CI/CD with multiple automated checks:

#### Test Workflow
- Runs tests on Ubuntu and macOS with Go 1.21, 1.22, and 1.23
- Executes tests with race detector
- Generates coverage reports (91.8% coverage)
- Uploads coverage to Codecov
- Runs `go vet` and `staticcheck`
- Runs `golangci-lint` for code quality
- Builds binaries for Linux, macOS, and Windows (amd64 and arm64)
- Uploads build artifacts (30-day retention)

#### Formatting Workflow
- Checks code formatting with `gofmt`
- Verifies import formatting with `goimports`
- Ensures `go.mod` and `go.sum` are tidy
- Fails if any formatting issues are found

#### Commit Lint Workflow
- Validates commit messages follow [Conventional Commits](https://www.conventionalcommits.org/)
- Checks PR titles match commit message format
- Ensures consistent commit history

#### Spellcheck Workflow
- Checks spelling in code, documentation, and comments
- Uses `cspell` with technical term dictionary
- Validates `.go`, `.md`, `.yml`, and `.yaml` files

#### SonarQube Workflow
- Performs comprehensive code quality and security analysis
- Uploads coverage reports to SonarCloud
- Analyzes code smells, bugs, vulnerabilities, and security hotspots
- Tracks code quality metrics over time
- Requires `SONAR_TOKEN` secret to be configured in repository settings

#### CodeQL Workflow
- GitHub's native security analysis for Go code
- Finds security vulnerabilities and coding errors
- Runs on push, pull requests, and weekly schedule (Mondays)
- Results appear in GitHub Security tab
- Uses both security and quality queries for comprehensive analysis

#### DCO Workflow
- Validates Developer Certificate of Origin compliance
- Ensures all commits are signed off with `Signed-off-by` line
- Required for all pull requests
- See [CONTRIBUTING.md](CONTRIBUTING.md) for details on signing commits

#### Dependabot
- Automatically checks for dependency updates weekly (every Monday)
- Creates pull requests for:
  - Go module dependencies (go.mod)
  - GitHub Actions versions
- Limits to 5 open PRs at a time to avoid clutter
- PRs are labeled with `dependencies` and ecosystem-specific tags
- Commit messages follow Conventional Commits format (`deps:` for Go modules, `ci:` for Actions)

#### GoReleaser Workflow
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

#### Release Drafter
- Automatically maintains draft releases
- Updates draft release on every push to main/master
- Generates changelog from merged PRs
- Categorizes changes by type (features, fixes, documentation, etc.)
- Auto-labels PRs based on branch names and titles
- Suggests next version number based on semver

#### PR Auto-Labeler
- Automatically labels PRs based on changed files
- Labels include: `documentation`, `voucher`, `cmd`, `tests`, `ci`, `dependencies`, `examples`, `configuration`
- Helps organize and filter pull requests
- Makes it easier to identify what areas of code are affected

#### PR Size Labeler
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

#### License Checker
- Verifies all dependencies have compatible licenses
- Runs on push, pull requests, and weekly schedule (Sundays)
- Generates license report for all dependencies
- Uploads report as workflow artifact (30-day retention)
- Helps ensure compliance with enterprise requirements

All workflows (except DCO and Release which run only on specific triggers) are triggered on pushes and pull requests to the `main` or `master` branch.

### Workflow Setup Requirements

Most workflows work out of the box, but some require additional configuration:

#### SonarQube
- Create a SonarCloud account at https://sonarcloud.io
- Add your repository to SonarCloud
- Add `SONAR_TOKEN` secret to GitHub repository settings
- Update `sonar.projectKey` and `sonar.organization` in `sonar-project.properties`

#### Quay.io Publishing
- Create a Quay.io account at https://quay.io
- Create a robot account or generate a personal access token
- Add these secrets to GitHub repository settings:
  - `QUAY_USERNAME`: Your Quay.io username or robot account name
  - `QUAY_TOKEN`: Your Quay.io access token

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on commit message format, code style, and contribution guidelines.

## Understanding the Output

### Text Format (Default)

The human-friendly text format displays:

- **Protocol Version**: Displayed as major.minor (e.g., "1.1" for version 101)
- **GUID**: The unique device identifier in hexadecimal format
- **Device Info**: Manufacturer-provided device description
- **Manufacturer Public Key**: The manufacturer's public key in PEM format with key type
- **Header HMAC**: HMAC algorithm and value protecting the header
- **Device Certificate Chain Hash**: Hash of the certificate chain (if present)
- **Rendezvous Information**: Decoded rendezvous directives with:
  - **IPAddress**: IP address for rendezvous server
  - **DNS**: DNS name for rendezvous server
  - **DevPort/OwnerPort**: TCP/UDP port numbers
  - **Protocol**: Protocol type (HTTP, HTTPS, etc.)
- **Device Certificate Chain**: Full certificate details including subject, issuer, validity dates, and serial numbers
- **Ownership Entries**: List of ownership transfers with public keys in PEM format

### JSON Format (--json flag)

The JSON format provides structured data suitable for programmatic processing with the same information in JSON structure.

## Related Resources

- [FIDO Device Onboard Specification](https://fidoalliance.org/specs/FDO/FIDO-Device-Onboard-PS-v1.1-20220419/)
- [go-fdo Library Documentation](https://pkg.go.dev/github.com/fido-device-onboard/go-fdo)
- [CBOR RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html)

## License

This project is licensed under the terms included in the LICENSE file.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
