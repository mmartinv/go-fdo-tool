package voucher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// Test data paths
const (
	testDataDir = "../../example"
)

func TestLoadFromFile(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{
			name:    "valid voucher",
			file:    filepath.Join(testDataDir, "voucher.pem"),
			wantErr: false,
		},
		{
			name:    "non-existent file",
			file:    "nonexistent.pem",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			voucher, err := LoadFromFile(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && voucher == nil {
				t.Error("LoadFromFile() returned nil voucher")
			}
			if !tt.wantErr {
				// Check that basic fields are present
				if voucher.Version == 0 {
					t.Error("Voucher version is 0")
				}
				if len(voucher.Header.Val.GUID) != 16 {
					t.Errorf("GUID length = %d, want 16", len(voucher.Header.Val.GUID))
				}
			}
		})
	}
}

func TestLoadFromFileInvalidPEM(t *testing.T) {
	// Create a temporary file with invalid PEM content
	tmpFile, err := os.CreateTemp("", "invalid-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Write invalid PEM data
	if _, err := tmpFile.Write([]byte("This is not valid PEM data")); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	_, err = LoadFromFile(tmpFile.Name())
	if err == nil {
		t.Error("LoadFromFile() should fail with invalid PEM data")
	}
	if !strings.Contains(err.Error(), "failed to decode PEM block") {
		t.Errorf("Expected 'failed to decode PEM block' error, got: %v", err)
	}
}

func TestSaveToFile(t *testing.T) {
	// Load a valid voucher
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "voucher-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Save the voucher
	if err := SaveToFile(voucher, tmpFile.Name()); err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Load it back
	loaded, err := LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load saved voucher: %v", err)
	}

	// Compare basic fields
	if loaded.Version != voucher.Version {
		t.Errorf("Version mismatch: got %v, want %v", loaded.Version, voucher.Version)
	}
	if string(loaded.Header.Val.GUID[:]) != string(voucher.Header.Val.GUID[:]) {
		t.Error("GUID mismatch")
	}
}

func TestToPEM(t *testing.T) {
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	pemData, err := ToPEM(voucher)
	if err != nil {
		t.Fatalf("ToPEM() error = %v", err)
	}

	// Check PEM format
	if !strings.HasPrefix(string(pemData), "-----BEGIN OWNERSHIP VOUCHER-----") {
		t.Error("PEM data doesn't start with correct header")
	}
	if !strings.HasSuffix(strings.TrimSpace(string(pemData)), "-----END OWNERSHIP VOUCHER-----") {
		t.Error("PEM data doesn't end with correct footer")
	}
}

func TestLoadPrivateKeyFromFile_PEM(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
		keyType string
	}{
		{
			name:    "valid EC key PEM",
			file:    filepath.Join(testDataDir, "owner_key.pem"),
			wantErr: false,
			keyType: "ecdsa",
		},
		{
			name:    "valid EC key DER",
			file:    filepath.Join(testDataDir, "owner_key.der"),
			wantErr: false,
			keyType: "ecdsa",
		},
		{
			name:    "non-existent file",
			file:    "nonexistent.key",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadPrivateKeyFromFile(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPrivateKeyFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if key == nil {
					t.Error("LoadPrivateKeyFromFile() returned nil key")
					return
				}
				// Check key type
				switch tt.keyType {
				case "ecdsa":
					if _, ok := key.(*ecdsa.PrivateKey); !ok {
						t.Errorf("Expected *ecdsa.PrivateKey, got %T", key)
					}
				case "rsa":
					if _, ok := key.(*rsa.PrivateKey); !ok {
						t.Errorf("Expected *rsa.PrivateKey, got %T", key)
					}
				}
			}
		})
	}
}

func TestLoadPrivateKeyFromFile_RSA(t *testing.T) {
	// Generate a temporary RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Save as PEM
	tmpFile, err := os.CreateTemp("", "rsa-key-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	if err := pem.Encode(tmpFile, pemBlock); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Load it back
	key, err := LoadPrivateKeyFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile() error = %v", err)
	}

	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("Expected *rsa.PrivateKey, got %T", key)
	}
}

func TestLoadPublicKeyOrCertFromFile(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		wantErr  bool
		wantCert bool
	}{
		{
			name:     "valid certificate",
			file:     filepath.Join(testDataDir, "new_owner_cert.pem"),
			wantErr:  false,
			wantCert: true,
		},
		{
			name:    "non-existent file",
			file:    "nonexistent.pem",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := LoadPublicKeyOrCertFromFile(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadPublicKeyOrCertFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if result == nil {
					t.Error("LoadPublicKeyOrCertFromFile() returned nil")
					return
				}
				if tt.wantCert {
					if _, ok := result.([]*x509.Certificate); !ok {
						t.Errorf("Expected certificate chain, got %T", result)
					}
				}
			}
		})
	}
}

func TestLoadPublicKeyOrCertFromFile_PublicKey(t *testing.T) {
	// Generate a temporary public key
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Save public key as PEM
	tmpFile, err := os.CreateTemp("", "pubkey-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	if err := pem.Encode(tmpFile, pemBlock); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	// Load it back
	result, err := LoadPublicKeyOrCertFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPublicKeyOrCertFromFile() error = %v", err)
	}

	if _, ok := result.(*ecdsa.PublicKey); !ok {
		t.Errorf("Expected *ecdsa.PublicKey, got %T", result)
	}
}

func TestExtend(t *testing.T) {
	// Load the test voucher
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	// Load the owner key
	ownerKey, err := LoadPrivateKeyFromFile(filepath.Join(testDataDir, "owner_key.pem"))
	if err != nil {
		t.Fatalf("Failed to load owner key: %v", err)
	}

	// Load the new owner certificate
	newOwner, err := LoadPublicKeyOrCertFromFile(filepath.Join(testDataDir, "new_owner_cert.pem"))
	if err != nil {
		t.Fatalf("Failed to load new owner cert: %v", err)
	}

	// Extend the voucher
	extended, err := Extend(voucher, ownerKey, newOwner)
	if err != nil {
		t.Fatalf("Extend() error = %v", err)
	}

	// Verify the extended voucher has one entry
	if len(extended.Entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(extended.Entries))
	}

	// Verify the entry has the correct structure
	if len(extended.Entries) > 0 {
		entry := extended.Entries[0]
		if entry.Payload.Val.PublicKey.Type == 0 {
			t.Error("Entry public key type is 0")
		}
		if len(entry.Payload.Val.PublicKey.Body) == 0 {
			t.Error("Entry public key body is empty")
		}
	}
}

func TestExtend_WrongOwnerKey(t *testing.T) {
	// Load the test voucher
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	// Generate a wrong owner key (not the one in the voucher)
	wrongOwnerKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Load the new owner certificate
	newOwner, err := LoadPublicKeyOrCertFromFile(filepath.Join(testDataDir, "new_owner_cert.pem"))
	if err != nil {
		t.Fatalf("Failed to load new owner cert: %v", err)
	}

	// Try to extend with wrong owner key - this should fail
	_, err = Extend(voucher, wrongOwnerKey, newOwner)
	if err == nil {
		t.Error("Extend() should fail with wrong owner key")
		return
	}
	// The error message varies depending on the failure mode
	if !strings.Contains(err.Error(), "did not match") && !strings.Contains(err.Error(), "verification") {
		t.Logf("Got error (expected): %v", err)
	}
}

func TestToText(t *testing.T) {
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	text := ToText(voucher)

	// Check for expected content
	expectedStrings := []string{
		"OWNERSHIP VOUCHER",
		"Protocol Version:",
		"GUID:",
		"Device Info:",
		"Manufacturer Public Key:",
		"Header HMAC:",
		"Rendezvous Information:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(text, expected) {
			t.Errorf("ToText() output missing expected string: %s", expected)
		}
	}
}

func TestToJSON(t *testing.T) {
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	jsonData, err := ToJSON(voucher)
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Check that it's valid JSON
	jsonStr := string(jsonData)
	if !strings.HasPrefix(jsonStr, "{") {
		t.Error("ToJSON() output doesn't start with '{'")
	}
	if !strings.HasSuffix(strings.TrimSpace(jsonStr), "}") {
		t.Error("ToJSON() output doesn't end with '}'")
	}

	// Check for expected fields
	expectedFields := []string{
		"\"version\"",
		"\"header\"",
		"\"headerHmac\"",
		"\"guid\"",
	}

	for _, expected := range expectedFields {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("ToJSON() output missing expected field: %s", expected)
		}
	}
}

func TestFormatVersion(t *testing.T) {
	tests := []struct {
		version uint16
		want    string
	}{
		{101, "1.1"},
		{100, "1.0"},
		{110, "1.10"},
		{200, "2.0"},
		{1234, "12.34"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatVersion(tt.version)
			if got != tt.want {
				t.Errorf("formatVersion(%d) = %s, want %s", tt.version, got, tt.want)
			}
		})
	}
}

func TestGetRvVarName(t *testing.T) {
	tests := []struct {
		rvVar protocol.RvVar
		want  string
	}{
		{protocol.RVIPAddress, "IPAddress"},
		{protocol.RVDevPort, "DevPort"},
		{protocol.RVOwnerPort, "OwnerPort"},
		{protocol.RVDns, "DNS"},
		{protocol.RVProtocol, "Protocol"},
		{protocol.RVMedium, "Medium"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getRvVarName(tt.rvVar)
			if got != tt.want {
				t.Errorf("getRvVarName(%v) = %s, want %s", tt.rvVar, got, tt.want)
			}
		})
	}
}

func TestGetProtocolName(t *testing.T) {
	tests := []struct {
		proto uint8
		want  string
	}{
		{0, "REST"},
		{1, "HTTP"},
		{2, "HTTPS"},
		{3, "TCP"},
		{4, "TLS"},
		{5, "CoAP-TCP"},
		{6, "CoAP-UDP"},
		{255, "Unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getProtocolName(tt.proto)
			if got != tt.want {
				t.Errorf("getProtocolName(%d) = %s, want %s", tt.proto, got, tt.want)
			}
		})
	}
}

func TestGetMediumName(t *testing.T) {
	tests := []struct {
		medium uint8
		want   string
	}{
		{20, "Ethernet"},
		{21, "WiFi"},
		{99, "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getMediumName(tt.medium)
			if got != tt.want {
				t.Errorf("getMediumName(%d) = %s, want %s", tt.medium, got, tt.want)
			}
		})
	}
}

func TestIsPrintable(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		{"printable ASCII", []byte("Hello World"), true},
		{"with numbers", []byte("Test123"), true},
		{"with symbols", []byte("test@example.com"), true},
		{"empty", []byte{}, false},
		{"with newline", []byte("test\n"), false},
		{"with null byte", []byte{0x00}, false},
		{"with high bytes", []byte{0xFF}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPrintable(tt.b)
			if got != tt.want {
				t.Errorf("isPrintable(%v) = %v, want %v", tt.b, got, tt.want)
			}
		})
	}
}

// Helper function to create a test certificate
func createTestCertificate(t *testing.T, key *ecdsa.PrivateKey) *x509.Certificate {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "Test Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	return cert
}

func TestFormatCertificate(t *testing.T) {
	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a test certificate
	cert := createTestCertificate(t, key)

	// Format it
	formatted := formatCertificate((*cbor.X509Certificate)(cert))

	// Check expected fields
	if formatted["subject"] == "" {
		t.Error("formatCertificate() missing subject")
	}
	if formatted["issuer"] == "" {
		t.Error("formatCertificate() missing issuer")
	}
	if formatted["notBefore"] == "" {
		t.Error("formatCertificate() missing notBefore")
	}
	if formatted["notAfter"] == "" {
		t.Error("formatCertificate() missing notAfter")
	}
	if formatted["serialNumber"] == "" {
		t.Error("formatCertificate() missing serialNumber")
	}
}

func TestFormatPublicKey(t *testing.T) {
	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create a protocol.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pk := protocol.PublicKey{
		Type: protocol.Secp384r1KeyType,
		Body: pubKeyBytes,
	}

	// Format it
	formatted := formatPublicKey(pk)

	// Check expected fields
	if formatted["type"] == "" {
		t.Error("formatPublicKey() missing type")
	}
	if formatted["publicKey"] == "" {
		t.Error("formatPublicKey() missing publicKey")
	}

	// Check PEM format
	pemStr, ok := formatted["publicKey"].(string)
	if !ok {
		t.Error("formatPublicKey() publicKey is not a string")
	}
	if !strings.Contains(pemStr, "-----BEGIN PUBLIC KEY-----") {
		t.Error("formatPublicKey() publicKey not in PEM format")
	}
}

func TestVerify_BasicChecks(t *testing.T) {
	// Test basic verification without secrets
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	result := Verify(voucher, nil)
	if !result.Passed {
		t.Error("Verify() basic checks failed for valid voucher")
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("  Check '%s' failed: %v", check.Name, check.Error)
			}
		}
	}

	// Verify expected checks were performed
	expectedChecks := []string{
		"Ownership Entries",
		"Certificate Chain Hash",
		"Device Certificate Chain",
		"Manufacturer Certificate Chain",
	}

	if len(result.Checks) < len(expectedChecks) {
		t.Errorf("Verify() performed %d checks, expected at least %d", len(result.Checks), len(expectedChecks))
	}

	for _, expectedCheck := range expectedChecks {
		found := false
		for _, check := range result.Checks {
			if check.Name == expectedCheck {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Verify() did not perform expected check: %s", expectedCheck)
		}
	}
}

func TestVerify_ExtendedVoucher(t *testing.T) {
	// Test verification of extended voucher
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "extended.pem"))
	if err != nil {
		t.Fatalf("Failed to load test extended voucher: %v", err)
	}

	result := Verify(voucher, nil)
	if !result.Passed {
		t.Error("Verify() failed for valid extended voucher")
		for _, check := range result.Checks {
			if !check.Passed {
				t.Errorf("  Check '%s' failed: %v", check.Name, check.Error)
			}
		}
	}
}

func TestParseHmacSecret(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:    "hex without prefix",
			input:   "deadbeef",
			want:    []byte{0xde, 0xad, 0xbe, 0xef},
			wantErr: false,
		},
		{
			name:    "hex with 0x prefix",
			input:   "0xdeadbeef",
			want:    []byte{0xde, 0xad, 0xbe, 0xef},
			wantErr: false,
		},
		{
			name:    "hex with 0X prefix",
			input:   "0Xdeadbeef",
			want:    []byte{0xde, 0xad, 0xbe, 0xef},
			wantErr: false,
		},
		{
			name:    "invalid hex",
			input:   "zzz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHmacSecret(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHmacSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ParseHmacSecret() length = %d, want %d", len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("ParseHmacSecret() byte[%d] = %x, want %x", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestLoadHmacSecretFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "voucher-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Test hex format file
	hexFile := filepath.Join(tmpDir, "secret.hex")
	if err := os.WriteFile(hexFile, []byte("deadbeef"), 0644); err != nil {
		t.Fatal(err)
	}

	secret, err := LoadHmacSecretFromFile(hexFile)
	if err != nil {
		t.Errorf("LoadHmacSecretFromFile() error = %v", err)
	}
	expected := []byte{0xde, 0xad, 0xbe, 0xef}
	if len(secret) != len(expected) {
		t.Errorf("LoadHmacSecretFromFile() length = %d, want %d", len(secret), len(expected))
	}
	for i := range secret {
		if secret[i] != expected[i] {
			t.Errorf("LoadHmacSecretFromFile() byte[%d] = %x, want %x", i, secret[i], expected[i])
		}
	}
}

func TestParsePublicKeyHash(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		hexStr    string
		wantAlg   protocol.HashAlg
		wantErr   bool
	}{
		{
			name:      "SHA256",
			algorithm: "SHA256",
			hexStr:    "abcd1234",
			wantAlg:   protocol.Sha256Hash,
			wantErr:   false,
		},
		{
			name:      "SHA-256",
			algorithm: "SHA-256",
			hexStr:    "abcd1234",
			wantAlg:   protocol.Sha256Hash,
			wantErr:   false,
		},
		{
			name:      "SHA384",
			algorithm: "SHA384",
			hexStr:    "abcd1234",
			wantAlg:   protocol.Sha384Hash,
			wantErr:   false,
		},
		{
			name:      "unsupported algorithm",
			algorithm: "MD5",
			hexStr:    "abcd1234",
			wantErr:   true,
		},
		{
			name:      "invalid hex",
			algorithm: "SHA256",
			hexStr:    "zzz",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := ParsePublicKeyHash(tt.algorithm, tt.hexStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePublicKeyHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if hash.Algorithm != tt.wantAlg {
					t.Errorf("ParsePublicKeyHash() algorithm = %v, want %v", hash.Algorithm, tt.wantAlg)
				}
			}
		})
	}
}

func TestLoadPublicKeyHashFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "voucher-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Test valid hash file
	hashFile := filepath.Join(tmpDir, "hash.txt")
	if err := os.WriteFile(hashFile, []byte("SHA256:abcd1234"), 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := LoadPublicKeyHashFromFile(hashFile)
	if err != nil {
		t.Errorf("LoadPublicKeyHashFromFile() error = %v", err)
	}
	if hash.Algorithm != protocol.Sha256Hash {
		t.Errorf("LoadPublicKeyHashFromFile() algorithm = %v, want %v", hash.Algorithm, protocol.Sha256Hash)
	}

	// Test invalid format
	invalidFile := filepath.Join(tmpDir, "invalid.txt")
	if err := os.WriteFile(invalidFile, []byte("invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LoadPublicKeyHashFromFile(invalidFile)
	if err == nil {
		t.Error("LoadPublicKeyHashFromFile() should error on invalid format")
	}
}

func TestLoadCACertsFromFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir, err := os.MkdirTemp("", "voucher-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate a test certificate
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := createTestCertificate(t, key)

	// Write certificate to PEM file
	certFile := filepath.Join(tmpDir, "ca.pem")
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	if err := os.WriteFile(certFile, pemData, 0644); err != nil {
		t.Fatal(err)
	}

	// Test loading
	pool, err := LoadCACertsFromFile(certFile)
	if err != nil {
		t.Errorf("LoadCACertsFromFile() error = %v", err)
	}
	if pool == nil {
		t.Error("LoadCACertsFromFile() returned nil pool")
	}

	// Test empty file
	emptyFile := filepath.Join(tmpDir, "empty.pem")
	if err := os.WriteFile(emptyFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}

	_, err = LoadCACertsFromFile(emptyFile)
	if err == nil {
		t.Error("LoadCACertsFromFile() should error on empty file")
	}
}
