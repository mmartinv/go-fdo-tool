package voucher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// Test formatRvInstruction for all RV variable types
func TestFormatRvInstruction_AllTypes(t *testing.T) {
	tests := []struct {
		name     string
		rvVar    protocol.RvVar
		value    []byte
		wantKey  string
		checkVal bool
	}{
		{
			name:     "IPAddress with CBOR",
			rvVar:    protocol.RVIPAddress,
			value:    mustCBORMarshal(t, []byte{192, 168, 1, 1}),
			wantKey:  "IPAddress",
			checkVal: true,
		},
		{
			name:     "IPAddress raw bytes",
			rvVar:    protocol.RVIPAddress,
			value:    []byte{192, 168, 1, 1},
			wantKey:  "IPAddress",
			checkVal: true,
		},
		{
			name:     "IPAddress invalid",
			rvVar:    protocol.RVIPAddress,
			value:    []byte{0x01, 0x02},
			wantKey:  "IPAddress",
			checkVal: true,
		},
		{
			name:     "DevPort with CBOR",
			rvVar:    protocol.RVDevPort,
			value:    mustCBORMarshal(t, uint16(8080)),
			wantKey:  "DevPort",
			checkVal: true,
		},
		{
			name:     "DevPort raw bytes",
			rvVar:    protocol.RVDevPort,
			value:    []byte{0x1F, 0x90}, // 8080 in big endian
			wantKey:  "DevPort",
			checkVal: true,
		},
		{
			name:     "DevPort invalid",
			rvVar:    protocol.RVDevPort,
			value:    []byte{0x01},
			wantKey:  "DevPort",
			checkVal: true,
		},
		{
			name:     "OwnerPort with CBOR",
			rvVar:    protocol.RVOwnerPort,
			value:    mustCBORMarshal(t, uint16(8082)),
			wantKey:  "OwnerPort",
			checkVal: true,
		},
		{
			name:     "DNS with CBOR",
			rvVar:    protocol.RVDns,
			value:    mustCBORMarshal(t, "example.com"),
			wantKey:  "DNS",
			checkVal: true,
		},
		{
			name:     "DNS raw string",
			rvVar:    protocol.RVDns,
			value:    []byte("example.com"),
			wantKey:  "DNS",
			checkVal: true,
		},
		{
			name:     "Protocol with CBOR",
			rvVar:    protocol.RVProtocol,
			value:    mustCBORMarshal(t, uint8(2)),
			wantKey:  "Protocol",
			checkVal: true,
		},
		{
			name:     "Protocol raw byte",
			rvVar:    protocol.RVProtocol,
			value:    []byte{1},
			wantKey:  "Protocol",
			checkVal: true,
		},
		{
			name:     "Protocol invalid",
			rvVar:    protocol.RVProtocol,
			value:    []byte{0x01, 0x02, 0x03},
			wantKey:  "Protocol",
			checkVal: true,
		},
		{
			name:     "Medium with CBOR",
			rvVar:    protocol.RVMedium,
			value:    mustCBORMarshal(t, uint8(20)),
			wantKey:  "Medium",
			checkVal: true,
		},
		{
			name:     "Medium raw byte",
			rvVar:    protocol.RVMedium,
			value:    []byte{21},
			wantKey:  "Medium",
			checkVal: true,
		},
		{
			name:     "Medium invalid",
			rvVar:    protocol.RVMedium,
			value:    []byte{0x01, 0x02, 0x03},
			wantKey:  "Medium",
			checkVal: true,
		},
		{
			name:     "Delaysec with CBOR",
			rvVar:    protocol.RVDelaysec,
			value:    mustCBORMarshal(t, uint16(300)),
			wantKey:  "Delaysec",
			checkVal: true,
		},
		{
			name:     "Delaysec raw bytes",
			rvVar:    protocol.RVDelaysec,
			value:    []byte{0x01, 0x2C}, // 300 in big endian
			wantKey:  "Delaysec",
			checkVal: true,
		},
		{
			name:     "Delaysec invalid",
			rvVar:    protocol.RVDelaysec,
			value:    []byte{0x01},
			wantKey:  "Delaysec",
			checkVal: true,
		},
		{
			name:     "DevOnly",
			rvVar:    protocol.RVDevOnly,
			value:    []byte("test"),
			wantKey:  "DevOnly",
			checkVal: false,
		},
		{
			name:     "OwnerOnly",
			rvVar:    protocol.RVOwnerOnly,
			value:    []byte("test"),
			wantKey:  "OwnerOnly",
			checkVal: false,
		},
		{
			name:     "SvCertHash",
			rvVar:    protocol.RVSvCertHash,
			value:    []byte("hash"),
			wantKey:  "SvCertHash",
			checkVal: false,
		},
		{
			name:     "ClCertHash",
			rvVar:    protocol.RVClCertHash,
			value:    []byte("hash"),
			wantKey:  "ClCertHash",
			checkVal: false,
		},
		{
			name:     "UserInput",
			rvVar:    protocol.RVUserInput,
			value:    []byte("input"),
			wantKey:  "UserInput",
			checkVal: false,
		},
		{
			name:     "WifiSsid",
			rvVar:    protocol.RVWifiSsid,
			value:    []byte("MyWiFi"),
			wantKey:  "WifiSsid",
			checkVal: false,
		},
		{
			name:     "WifiPw",
			rvVar:    protocol.RVWifiPw,
			value:    []byte("password"),
			wantKey:  "WifiPw",
			checkVal: false,
		},
		{
			name:     "Bypass",
			rvVar:    protocol.RVBypass,
			value:    []byte("bypass"),
			wantKey:  "Bypass",
			checkVal: false,
		},
		{
			name:     "ExtRV",
			rvVar:    protocol.RVExtRV,
			value:    []byte("ext"),
			wantKey:  "ExtRV",
			checkVal: false,
		},
		{
			name:     "Non-printable data",
			rvVar:    protocol.RVDevOnly,
			value:    []byte{0x00, 0x01, 0xFF},
			wantKey:  "DevOnly",
			checkVal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instr := protocol.RvInstruction{
				Variable: tt.rvVar,
				Value:    tt.value,
			}
			result := formatRvInstruction(instr)
			if _, ok := result[tt.wantKey]; !ok {
				t.Errorf("formatRvInstruction() missing key %s, got keys: %v", tt.wantKey, getKeys(result))
			}
		})
	}
}

// Test formatRvValue for all RV variable types
func TestFormatRvValue_AllTypes(t *testing.T) {
	tests := []struct {
		name    string
		rvVar   protocol.RvVar
		value   []byte
		wantStr string
	}{
		{
			name:    "IPAddress",
			rvVar:   protocol.RVIPAddress,
			value:   mustCBORMarshal(t, []byte{192, 168, 1, 1}),
			wantStr: "192.168.1.1",
		},
		{
			name:    "DevPort",
			rvVar:   protocol.RVDevPort,
			value:   mustCBORMarshal(t, uint16(8080)),
			wantStr: "8080",
		},
		{
			name:    "DNS",
			rvVar:   protocol.RVDns,
			value:   mustCBORMarshal(t, "example.com"),
			wantStr: "example.com",
		},
		{
			name:    "Protocol HTTP",
			rvVar:   protocol.RVProtocol,
			value:   mustCBORMarshal(t, uint8(1)),
			wantStr: "HTTP",
		},
		{
			name:    "Medium Ethernet",
			rvVar:   protocol.RVMedium,
			value:   mustCBORMarshal(t, uint8(20)),
			wantStr: "Ethernet",
		},
		{
			name:    "Delaysec",
			rvVar:   protocol.RVDelaysec,
			value:   mustCBORMarshal(t, uint16(120)),
			wantStr: "120 seconds",
		},
		{
			name:    "Printable string",
			rvVar:   protocol.RVDevOnly,
			value:   []byte("test"),
			wantStr: "test",
		},
		{
			name:    "Non-printable bytes",
			rvVar:   protocol.RVDevOnly,
			value:   []byte{0x00, 0xFF},
			wantStr: "0x00ff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instr := protocol.RvInstruction{
				Variable: tt.rvVar,
				Value:    tt.value,
			}
			result := formatRvValue(instr)
			if !strings.Contains(result, tt.wantStr) && tt.wantStr != "" {
				t.Errorf("formatRvValue() = %s, want to contain %s", result, tt.wantStr)
			}
		})
	}
}

// Test all RvVar names
func TestGetRvVarName_AllTypes(t *testing.T) {
	tests := []struct {
		rvVar protocol.RvVar
		want  string
	}{
		{protocol.RVDevOnly, "DevOnly"},
		{protocol.RVOwnerOnly, "OwnerOnly"},
		{protocol.RVIPAddress, "IPAddress"},
		{protocol.RVDevPort, "DevPort"},
		{protocol.RVOwnerPort, "OwnerPort"},
		{protocol.RVDns, "DNS"},
		{protocol.RVSvCertHash, "SvCertHash"},
		{protocol.RVClCertHash, "ClCertHash"},
		{protocol.RVUserInput, "UserInput"},
		{protocol.RVWifiSsid, "WifiSsid"},
		{protocol.RVWifiPw, "WifiPw"},
		{protocol.RVMedium, "Medium"},
		{protocol.RVProtocol, "Protocol"},
		{protocol.RVDelaysec, "Delaysec"},
		{protocol.RVBypass, "Bypass"},
		{protocol.RVExtRV, "ExtRV"},
		{protocol.RvVar(99), "Unknown(99)"},
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

// Test Extend with RSA keys
func TestExtend_RSA(t *testing.T) {
	// This test would require an RSA-based voucher
	// Skip if we don't have one
	t.Skip("Skipping RSA test - would need RSA voucher")
}

// Test Extend with unsupported type
func TestExtend_UnsupportedType(t *testing.T) {
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	ownerKey, err := LoadPrivateKeyFromFile(filepath.Join(testDataDir, "owner_key.pem"))
	if err != nil {
		t.Fatalf("Failed to load owner key: %v", err)
	}

	// Try to extend with unsupported type (plain string)
	_, err = Extend(voucher, ownerKey, "not a valid key type")
	if err == nil {
		t.Error("Extend() should fail with unsupported type")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("Expected unsupported type error, got: %v", err)
	}
}

// Test LoadPrivateKeyFromFile with PKCS8 format
func TestLoadPrivateKeyFromFile_PKCS8(t *testing.T) {
	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal as PKCS8
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	// Save as PEM
	tmpFile, err := os.CreateTemp("", "pkcs8-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	if err := pem.Encode(tmpFile, pemBlock); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	// Load it back
	key, err := LoadPrivateKeyFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile() error = %v", err)
	}

	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Expected *ecdsa.PrivateKey, got %T", key)
	}
}

// Test LoadPrivateKeyFromFile with RSA PKCS8
func TestLoadPrivateKeyFromFile_RSA_PKCS8(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal as PKCS8
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}

	// Save as PEM
	tmpFile, err := os.CreateTemp("", "rsa-pkcs8-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	}
	if err := pem.Encode(tmpFile, pemBlock); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	// Load it back
	key, err := LoadPrivateKeyFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile() error = %v", err)
	}

	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("Expected *rsa.PrivateKey, got %T", key)
	}
}

// Test LoadPrivateKeyFromFile with DER EC key
func TestLoadPrivateKeyFromFile_DER_EC(t *testing.T) {
	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal as DER
	derBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	// Save as raw DER
	tmpFile, err := os.CreateTemp("", "ec-der-*.der")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(derBytes); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	// Load it back
	key, err := LoadPrivateKeyFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile() error = %v", err)
	}

	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Expected *ecdsa.PrivateKey, got %T", key)
	}
}

// Test LoadPrivateKeyFromFile with DER PKCS8
func TestLoadPrivateKeyFromFile_DER_PKCS8(t *testing.T) {
	// Generate an ECDSA key
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal as PKCS8 DER
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	// Save as raw DER
	tmpFile, err := os.CreateTemp("", "pkcs8-der-*.der")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(pkcs8Bytes); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	// Load it back
	key, err := LoadPrivateKeyFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile() error = %v", err)
	}

	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Expected *ecdsa.PrivateKey, got %T", key)
	}
}

// Test LoadPrivateKeyFromFile with DER RSA PKCS1
func TestLoadPrivateKeyFromFile_DER_RSA_PKCS1(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Marshal as PKCS1 DER
	derBytes := x509.MarshalPKCS1PrivateKey(rsaKey)

	// Save as raw DER
	tmpFile, err := os.CreateTemp("", "rsa-pkcs1-der-*.der")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(derBytes); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	// Load it back
	key, err := LoadPrivateKeyFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFromFile() error = %v", err)
	}

	if _, ok := key.(*rsa.PrivateKey); !ok {
		t.Errorf("Expected *rsa.PrivateKey, got %T", key)
	}
}

// Test LoadPrivateKeyFromFile with invalid DER
func TestLoadPrivateKeyFromFile_InvalidDER(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "invalid-der-*.der")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Write invalid DER data
	if _, err := tmpFile.Write([]byte{0x01, 0x02, 0x03, 0x04}); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	_, err = LoadPrivateKeyFromFile(tmpFile.Name())
	if err == nil {
		t.Error("LoadPrivateKeyFromFile() should fail with invalid DER")
	}
}

// Test LoadPublicKeyOrCertFromFile with RSA public key
func TestLoadPublicKeyOrCertFromFile_RSA(t *testing.T) {
	// Generate an RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Save public key as PEM
	tmpFile, err := os.CreateTemp("", "rsa-pubkey-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
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
	_ = tmpFile.Close()

	// Load it back
	result, err := LoadPublicKeyOrCertFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("LoadPublicKeyOrCertFromFile() error = %v", err)
	}

	if _, ok := result.(*rsa.PublicKey); !ok {
		t.Errorf("Expected *rsa.PublicKey, got %T", result)
	}
}

// Test formatHmac and formatHash
func TestFormatHmacAndHash(t *testing.T) {
	hmac := protocol.Hmac{
		Algorithm: protocol.HmacSha256Hash,
		Value:     []byte{0x01, 0x02, 0x03, 0x04},
	}

	result := formatHmac(hmac)
	if result["algorithm"] == "" {
		t.Error("formatHmac() missing algorithm")
	}
	if result["value"] == "" {
		t.Error("formatHmac() missing value")
	}

	hash := protocol.Hash{
		Algorithm: protocol.Sha256Hash,
		Value:     []byte{0x01, 0x02, 0x03, 0x04},
	}

	hashResult := formatHash(hash)
	if hashResult["algorithm"] == "" {
		t.Error("formatHash() missing algorithm")
	}
	if hashResult["value"] == "" {
		t.Error("formatHash() missing value")
	}
}

// Test splitLines edge cases
func TestSplitLines_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty string", "", 0},
		{"single line no newline", "test", 1},
		{"single line with newline", "test\n", 1},
		{"multiple lines", "line1\nline2\nline3", 3},
		{"trailing newline", "line1\nline2\n", 2},
		{"multiple trailing newlines", "line1\n\n\n", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitLines(tt.input)
			if len(got) != tt.want {
				t.Errorf("splitLines() returned %d lines, want %d", len(got), tt.want)
			}
		})
	}
}

// Helper functions

func mustCBORMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := cbor.Marshal(v)
	if err != nil {
		t.Fatalf("Failed to marshal CBOR: %v", err)
	}
	return data
}

func getKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Test ToText with extended voucher
func TestToText_WithEntries(t *testing.T) {
	// Load and extend a voucher
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	ownerKey, err := LoadPrivateKeyFromFile(filepath.Join(testDataDir, "owner_key.pem"))
	if err != nil {
		t.Fatalf("Failed to load owner key: %v", err)
	}

	newOwner, err := LoadPublicKeyOrCertFromFile(filepath.Join(testDataDir, "new_owner_cert.pem"))
	if err != nil {
		t.Fatalf("Failed to load new owner cert: %v", err)
	}

	extended, err := Extend(voucher, ownerKey, newOwner)
	if err != nil {
		t.Fatalf("Failed to extend voucher: %v", err)
	}

	text := ToText(extended)

	// Check for ownership entries section
	if !strings.Contains(text, "Ownership Entries") {
		t.Error("ToText() with extended voucher should contain 'Ownership Entries'")
	}
	if !strings.Contains(text, "Entry 1:") {
		t.Error("ToText() with extended voucher should contain 'Entry 1:'")
	}
	if !strings.Contains(text, "Previous Hash:") {
		t.Error("ToText() with extended voucher should contain 'Previous Hash:'")
	}
}

// Test ToJSON with extended voucher
func TestToJSON_WithEntries(t *testing.T) {
	// Load and extend a voucher
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	ownerKey, err := LoadPrivateKeyFromFile(filepath.Join(testDataDir, "owner_key.pem"))
	if err != nil {
		t.Fatalf("Failed to load owner key: %v", err)
	}

	newOwner, err := LoadPublicKeyOrCertFromFile(filepath.Join(testDataDir, "new_owner_cert.pem"))
	if err != nil {
		t.Fatalf("Failed to load new owner cert: %v", err)
	}

	extended, err := Extend(voucher, ownerKey, newOwner)
	if err != nil {
		t.Fatalf("Failed to extend voucher: %v", err)
	}

	jsonData, err := ToJSON(extended)
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	jsonStr := string(jsonData)
	if !strings.Contains(jsonStr, "\"entries\"") {
		t.Error("ToJSON() with extended voucher should contain 'entries' field")
	}
	if !strings.Contains(jsonStr, "\"previousHash\"") {
		t.Error("ToJSON() with extended voucher should contain 'previousHash'")
	}
}

// Test SaveToFile error handling
func TestSaveToFile_InvalidPath(t *testing.T) {
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	// Try to save to an invalid path
	err = SaveToFile(voucher, "/invalid/path/that/does/not/exist/voucher.pem")
	if err == nil {
		t.Error("SaveToFile() should fail with invalid path")
	}
}

// Test ToPEM error handling (though it's hard to make it fail)
func TestToPEM_Success(t *testing.T) {
	voucher, err := LoadFromFile(filepath.Join(testDataDir, "voucher.pem"))
	if err != nil {
		t.Fatalf("Failed to load test voucher: %v", err)
	}

	pemData, err := ToPEM(voucher)
	if err != nil {
		t.Fatalf("ToPEM() error = %v", err)
	}

	if len(pemData) == 0 {
		t.Error("ToPEM() returned empty data")
	}
}

// Test LoadFromFile with wrong PEM type
func TestLoadFromFile_WrongPEMType(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "wrong-type-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	// Write a certificate PEM instead of voucher
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte("fake certificate data"),
	}
	if err := pem.Encode(tmpFile, pemBlock); err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()

	_, err = LoadFromFile(tmpFile.Name())
	if err == nil {
		t.Error("LoadFromFile() should fail with wrong PEM type")
	}
	if !strings.Contains(err.Error(), "invalid PEM block type") {
		t.Errorf("Expected 'invalid PEM block type' error, got: %v", err)
	}
}

// Test LoadPublicKeyOrCertFromFile with empty file
func TestLoadPublicKeyOrCertFromFile_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "empty-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	_ = tmpFile.Close()
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	_, err = LoadPublicKeyOrCertFromFile(tmpFile.Name())
	if err == nil {
		t.Error("LoadPublicKeyOrCertFromFile() should fail with empty file")
	}
}
