package keygen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// KeyType represents the type of key to generate
type KeyType string

const (
	// ECDSA key types
	KeyTypeECDSAP256 KeyType = "ecdsa-p256" // secp256r1 / NIST P-256 / prime256v1
	KeyTypeECDSAP384 KeyType = "ecdsa-p384" // secp384r1 / NIST P-384

	// RSA key types
	KeyTypeRSA2048 KeyType = "rsa-2048" // RSA 2048 bits
	KeyTypeRSA3072 KeyType = "rsa-3072" // RSA 3072 bits
	KeyTypeRSA4096 KeyType = "rsa-4096" // RSA 4096 bits
)

// Format represents the output format for the key
type Format string

const (
	FormatPEM Format = "pem" // PEM encoded
	FormatDER Format = "der" // DER encoded (raw binary)
)

// GenerateKey generates a new private key of the specified type
func GenerateKey(keyType KeyType) (crypto.Signer, error) {
	switch keyType {
	case KeyTypeECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyTypeECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyTypeRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyTypeRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyTypeRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// EncodePrivateKey encodes a private key in the specified format
func EncodePrivateKey(key crypto.Signer, format Format) ([]byte, error) {
	// Marshal to PKCS#8 DER format
	derBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// If DER format, return as-is
	if format == FormatDER {
		return derBytes, nil
	}

	// If PEM format, encode
	if format == FormatPEM {
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		}
		return pem.EncodeToMemory(pemBlock), nil
	}

	return nil, fmt.Errorf("unsupported format: %s", format)
}

// EncodePublicKey encodes a public key in the specified format
func EncodePublicKey(key crypto.PublicKey, format Format) ([]byte, error) {
	// Marshal to PKIX DER format
	derBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// If DER format, return as-is
	if format == FormatDER {
		return derBytes, nil
	}

	// If PEM format, encode
	if format == FormatPEM {
		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		}
		return pem.EncodeToMemory(pemBlock), nil
	}

	return nil, fmt.Errorf("unsupported format: %s", format)
}

// SavePrivateKey saves a private key to a file
func SavePrivateKey(key crypto.Signer, path string, format Format) error {
	data, err := EncodePrivateKey(key, format)
	if err != nil {
		return err
	}

	// Set restrictive permissions for private keys (0600 = owner read/write only)
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// SavePublicKey saves a public key to a file
func SavePublicKey(key crypto.PublicKey, path string, format Format) error {
	data, err := EncodePublicKey(key, format)
	if err != nil {
		return err
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}

// GetKeyInfo returns human-readable information about a key
func GetKeyInfo(key crypto.Signer) map[string]string {
	info := make(map[string]string)

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		info["type"] = "ECDSA"
		info["curve"] = k.Curve.Params().Name
		info["bits"] = fmt.Sprintf("%d", k.Curve.Params().BitSize)
	case *rsa.PrivateKey:
		info["type"] = "RSA"
		info["bits"] = fmt.Sprintf("%d", k.N.BitLen())
	default:
		info["type"] = "Unknown"
	}

	return info
}

// ParseKeyType parses a key type string
func ParseKeyType(s string) (KeyType, error) {
	switch s {
	case "ecdsa-p256", "secp256r1", "p256", "prime256v1":
		return KeyTypeECDSAP256, nil
	case "ecdsa-p384", "secp384r1", "p384":
		return KeyTypeECDSAP384, nil
	case "rsa-2048", "rsa2048", "2048":
		return KeyTypeRSA2048, nil
	case "rsa-3072", "rsa3072", "3072":
		return KeyTypeRSA3072, nil
	case "rsa-4096", "rsa4096", "4096":
		return KeyTypeRSA4096, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s (supported: ecdsa-p256, ecdsa-p384, rsa-2048, rsa-3072, rsa-4096)", s)
	}
}

// ParseFormat parses a format string
func ParseFormat(s string) (Format, error) {
	switch s {
	case "pem":
		return FormatPEM, nil
	case "der":
		return FormatDER, nil
	default:
		return "", fmt.Errorf("unsupported format: %s (supported: pem, der)", s)
	}
}

// SupportedKeyTypes returns a list of supported key type strings
func SupportedKeyTypes() []string {
	return []string{
		"ecdsa-p256 (secp256r1, NIST P-256)",
		"ecdsa-p384 (secp384r1, NIST P-384)",
		"rsa-2048",
		"rsa-3072",
		"rsa-4096",
	}
}

// KeyTypeInfo represents information about a key type
type KeyTypeInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Aliases     []string `json:"aliases,omitempty"`
	Recommended bool     `json:"recommended,omitempty"`
}

// GetSupportedKeyTypesInfo returns detailed information about all supported key types
func GetSupportedKeyTypesInfo() []KeyTypeInfo {
	return []KeyTypeInfo{
		{
			Name:        "ecdsa-p256",
			Description: "ECDSA with NIST P-256 curve (256-bit)",
			Aliases:     []string{"secp256r1", "p256", "prime256v1"},
			Recommended: false,
		},
		{
			Name:        "ecdsa-p384",
			Description: "ECDSA with NIST P-384 curve (384-bit)",
			Aliases:     []string{"secp384r1", "p384"},
			Recommended: true,
		},
		{
			Name:        "rsa-2048",
			Description: "RSA with 2048-bit key",
			Aliases:     []string{"rsa2048", "2048"},
			Recommended: false,
		},
		{
			Name:        "rsa-3072",
			Description: "RSA with 3072-bit key",
			Aliases:     []string{"rsa3072", "3072"},
			Recommended: false,
		},
		{
			Name:        "rsa-4096",
			Description: "RSA with 4096-bit key",
			Aliases:     []string{"rsa4096", "4096"},
			Recommended: false,
		},
	}
}
