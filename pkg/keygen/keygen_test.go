package keygen

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		wantErr bool
	}{
		{"ECDSA P-256", KeyTypeECDSAP256, false},
		{"ECDSA P-384", KeyTypeECDSAP384, false},
		{"RSA 2048", KeyTypeRSA2048, false},
		{"RSA 3072", KeyTypeRSA3072, false},
		{"RSA 4096", KeyTypeRSA4096, false},
		{"Invalid", KeyType("invalid"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.keyType)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("GenerateKey() returned nil key")
			}
		})
	}
}

func TestGenerateKeyTypes(t *testing.T) {
	tests := []struct {
		name      string
		keyType   KeyType
		checkType func(interface{}) bool
	}{
		{
			name:    "ECDSA P-256",
			keyType: KeyTypeECDSAP256,
			checkType: func(k interface{}) bool {
				ecKey, ok := k.(*ecdsa.PrivateKey)
				return ok && ecKey.Curve.Params().BitSize == 256
			},
		},
		{
			name:    "ECDSA P-384",
			keyType: KeyTypeECDSAP384,
			checkType: func(k interface{}) bool {
				ecKey, ok := k.(*ecdsa.PrivateKey)
				return ok && ecKey.Curve.Params().BitSize == 384
			},
		},
		{
			name:    "RSA 2048",
			keyType: KeyTypeRSA2048,
			checkType: func(k interface{}) bool {
				rsaKey, ok := k.(*rsa.PrivateKey)
				return ok && rsaKey.N.BitLen() == 2048
			},
		},
		{
			name:    "RSA 3072",
			keyType: KeyTypeRSA3072,
			checkType: func(k interface{}) bool {
				rsaKey, ok := k.(*rsa.PrivateKey)
				return ok && rsaKey.N.BitLen() == 3072
			},
		},
		{
			name:    "RSA 4096",
			keyType: KeyTypeRSA4096,
			checkType: func(k interface{}) bool {
				rsaKey, ok := k.(*rsa.PrivateKey)
				return ok && rsaKey.N.BitLen() == 4096
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.keyType)
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}
			if !tt.checkType(key) {
				t.Errorf("GenerateKey() generated wrong key type")
			}
		})
	}
}

func TestEncodePrivateKey(t *testing.T) {
	key, err := GenerateKey(KeyTypeECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	tests := []struct {
		name    string
		format  Format
		wantErr bool
		check   func([]byte) bool
	}{
		{
			name:    "PEM format",
			format:  FormatPEM,
			wantErr: false,
			check: func(data []byte) bool {
				return strings.HasPrefix(string(data), "-----BEGIN PRIVATE KEY-----")
			},
		},
		{
			name:    "DER format",
			format:  FormatDER,
			wantErr: false,
			check: func(data []byte) bool {
				// DER is binary, just check it's not empty
				return len(data) > 0
			},
		},
		{
			name:    "Invalid format",
			format:  Format("invalid"),
			wantErr: true,
			check:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodePrivateKey(key, tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil && !tt.check(data) {
				t.Error("EncodePrivateKey() produced invalid output")
			}
		})
	}
}

func TestEncodePublicKey(t *testing.T) {
	key, err := GenerateKey(KeyTypeECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	pubKey := key.Public()

	tests := []struct {
		name    string
		format  Format
		wantErr bool
		check   func([]byte) bool
	}{
		{
			name:    "PEM format",
			format:  FormatPEM,
			wantErr: false,
			check: func(data []byte) bool {
				return strings.HasPrefix(string(data), "-----BEGIN PUBLIC KEY-----")
			},
		},
		{
			name:    "DER format",
			format:  FormatDER,
			wantErr: false,
			check: func(data []byte) bool {
				return len(data) > 0
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := EncodePublicKey(pubKey, tt.format)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncodePublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.check != nil && !tt.check(data) {
				t.Error("EncodePublicKey() produced invalid output")
			}
		})
	}
}

func TestSaveAndLoadPrivateKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keygen-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := GenerateKey(KeyTypeECDSAP384)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test PEM format
	pemPath := filepath.Join(tmpDir, "key.pem")
	if err := SavePrivateKey(key, pemPath, FormatPEM); err != nil {
		t.Errorf("SavePrivateKey() PEM error = %v", err)
	}

	// Verify file exists and has correct permissions
	info, err := os.Stat(pemPath)
	if err != nil {
		t.Errorf("Failed to stat PEM file: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("PEM file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Verify PEM content
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		t.Errorf("Failed to read PEM file: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Error("Invalid PEM format")
	}

	// Test DER format
	derPath := filepath.Join(tmpDir, "key.der")
	if err := SavePrivateKey(key, derPath, FormatDER); err != nil {
		t.Errorf("SavePrivateKey() DER error = %v", err)
	}

	// Verify DER content
	derData, err := os.ReadFile(derPath)
	if err != nil {
		t.Errorf("Failed to read DER file: %v", err)
	}
	_, err = x509.ParsePKCS8PrivateKey(derData)
	if err != nil {
		t.Errorf("Invalid DER format: %v", err)
	}
}

func TestSavePublicKey(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "keygen-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key, err := GenerateKey(KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	pubKey := key.Public()

	// Test PEM format
	pemPath := filepath.Join(tmpDir, "key_pub.pem")
	if err := SavePublicKey(pubKey, pemPath, FormatPEM); err != nil {
		t.Errorf("SavePublicKey() PEM error = %v", err)
	}

	// Verify PEM content
	pemData, err := os.ReadFile(pemPath)
	if err != nil {
		t.Errorf("Failed to read PEM file: %v", err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Error("Invalid PEM format")
	}
}

func TestSavePrivateKey_ErrorCases(t *testing.T) {
	key, err := GenerateKey(KeyTypeECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test with invalid path (directory that doesn't exist)
	err = SavePrivateKey(key, "/nonexistent/directory/key.pem", FormatPEM)
	if err == nil {
		t.Error("SavePrivateKey should error when writing to invalid path")
	}
}

func TestSavePublicKey_ErrorCases(t *testing.T) {
	key, err := GenerateKey(KeyTypeECDSAP256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	pubKey := key.Public()

	// Test with invalid path (directory that doesn't exist)
	err = SavePublicKey(pubKey, "/nonexistent/directory/key_pub.pem", FormatPEM)
	if err == nil {
		t.Error("SavePublicKey should error when writing to invalid path")
	}
}

func TestGetKeyInfo(t *testing.T) {
	tests := []struct {
		name     string
		keyType  KeyType
		wantType string
		wantBits string
	}{
		{"ECDSA P-256", KeyTypeECDSAP256, "ECDSA", "256"},
		{"ECDSA P-384", KeyTypeECDSAP384, "ECDSA", "384"},
		{"RSA 2048", KeyTypeRSA2048, "RSA", "2048"},
		{"RSA 4096", KeyTypeRSA4096, "RSA", "4096"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateKey(tt.keyType)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			info := GetKeyInfo(key)
			if info["type"] != tt.wantType {
				t.Errorf("GetKeyInfo() type = %v, want %v", info["type"], tt.wantType)
			}
			if info["bits"] != tt.wantBits {
				t.Errorf("GetKeyInfo() bits = %v, want %v", info["bits"], tt.wantBits)
			}
		})
	}
}

func TestParseKeyType(t *testing.T) {
	tests := []struct {
		input   string
		want    KeyType
		wantErr bool
	}{
		{"ecdsa-p256", KeyTypeECDSAP256, false},
		{"secp256r1", KeyTypeECDSAP256, false},
		{"p256", KeyTypeECDSAP256, false},
		{"prime256v1", KeyTypeECDSAP256, false},
		{"ecdsa-p384", KeyTypeECDSAP384, false},
		{"secp384r1", KeyTypeECDSAP384, false},
		{"p384", KeyTypeECDSAP384, false},
		{"rsa-2048", KeyTypeRSA2048, false},
		{"rsa2048", KeyTypeRSA2048, false},
		{"2048", KeyTypeRSA2048, false},
		{"rsa-3072", KeyTypeRSA3072, false},
		{"rsa-4096", KeyTypeRSA4096, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseKeyType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseKeyType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseKeyType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input   string
		want    Format
		wantErr bool
	}{
		{"pem", FormatPEM, false},
		{"der", FormatDER, false},
		{"invalid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseFormat(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseFormat() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSupportedKeyTypes(t *testing.T) {
	types := SupportedKeyTypes()
	if len(types) != 5 {
		t.Errorf("SupportedKeyTypes() returned %d types, want 5", len(types))
	}
}

func TestGetSupportedKeyTypesInfo(t *testing.T) {
	info := GetSupportedKeyTypesInfo()
	if len(info) != 5 {
		t.Errorf("GetSupportedKeyTypesInfo() returned %d types, want 5", len(info))
	}

	// Verify all key types have required fields
	for _, keyInfo := range info {
		if keyInfo.Name == "" {
			t.Error("Key type info has empty Name")
		}
		if keyInfo.Description == "" {
			t.Error("Key type info has empty Description")
		}
	}

	// Verify ECDSA P-384 is marked as recommended
	foundRecommended := false
	for _, keyInfo := range info {
		if keyInfo.Name == "ecdsa-p384" {
			if !keyInfo.Recommended {
				t.Error("ECDSA P-384 should be recommended")
			}
			foundRecommended = true
			if len(keyInfo.Aliases) == 0 {
				t.Error("ECDSA P-384 should have aliases")
			}
		}
	}
	if !foundRecommended {
		t.Error("No recommended key type found")
	}
}
