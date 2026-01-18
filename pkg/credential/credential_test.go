package credential

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// Test data paths
const (
	testDataDir = "testdata"
)

func TestLoadFromFile(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{
			name:    "valid credential",
			file:    filepath.Join(testDataDir, "device_credential.cbor"),
			wantErr: false,
		},
		{
			name:    "non-existent file",
			file:    "nonexistent.cbor",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred, err := LoadFromFile(tt.file)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadFromFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && cred == nil {
				t.Error("LoadFromFile() returned nil credential")
			}
		})
	}
}

func TestSaveToFile(t *testing.T) {
	// Create a test credential
	cred := createTestCredential(t)

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "credential-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Save credential
	testFile := filepath.Join(tmpDir, "test_cred.cbor")
	if err := SaveToFile(cred, testFile); err != nil {
		t.Errorf("SaveToFile() error = %v", err)
	}

	// Load it back
	loaded, err := LoadFromFile(testFile)
	if err != nil {
		t.Errorf("LoadFromFile() after save error = %v", err)
	}

	// Verify basic fields match
	if loaded.Active != cred.Active {
		t.Errorf("Active mismatch: got %v, want %v", loaded.Active, cred.Active)
	}
	if loaded.DeviceInfo != cred.DeviceInfo {
		t.Errorf("DeviceInfo mismatch: got %v, want %v", loaded.DeviceInfo, cred.DeviceInfo)
	}
}

func TestToText(t *testing.T) {
	cred, err := LoadFromFile(filepath.Join(testDataDir, "device_credential.cbor"))
	if err != nil {
		t.Fatalf("Failed to load test credential: %v", err)
	}

	text := ToText(cred, false)

	// Check for expected strings
	expectedStrings := []string{
		"DEVICE CREDENTIAL",
		"Active:",
		"Protocol Version:",
		"GUID:",
		"Device Info:",
		"Public Key Hash:",
		"Rendezvous Information:",
		"Private Key:",
		"Type:",
		"Size:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(text, expected) {
			t.Errorf("ToText() output missing expected string: %s", expected)
		}
	}

	// Check that secrets are hidden by default
	if !strings.Contains(text, "(hidden, use --show-secrets to display)") {
		t.Error("ToText() should hide secrets by default")
	}
}

func TestToTextWithSecrets(t *testing.T) {
	cred, err := LoadFromFile(filepath.Join(testDataDir, "device_credential.cbor"))
	if err != nil {
		t.Fatalf("Failed to load test credential: %v", err)
	}

	text := ToText(cred, true)

	// Check that secrets are shown
	if !strings.Contains(text, "-----BEGIN PRIVATE KEY-----") {
		t.Error("ToText(showSecrets=true) should show private key in PEM format")
	}
	if strings.Contains(text, "(hidden") {
		t.Error("ToText(showSecrets=true) should not hide any secrets")
	}
}

func TestToJSON(t *testing.T) {
	cred, err := LoadFromFile(filepath.Join(testDataDir, "device_credential.cbor"))
	if err != nil {
		t.Fatalf("Failed to load test credential: %v", err)
	}

	jsonData, err := ToJSON(cred, false)
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
		"\"active\"",
		"\"version\"",
		"\"guid\"",
		"\"deviceInfo\"",
		"\"publicKeyHash\"",
		"\"rvInfo\"",
		"\"privateKey\"",
		"\"type\"",
		"\"bits\"",
	}

	for _, expected := range expectedFields {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("ToJSON() output missing expected field: %s", expected)
		}
	}

	// Check that secrets are hidden
	if !strings.Contains(jsonStr, "\"(hidden)\"") {
		t.Error("ToJSON() should hide secrets by default")
	}
}

func TestToJSONWithSecrets(t *testing.T) {
	cred, err := LoadFromFile(filepath.Join(testDataDir, "device_credential.cbor"))
	if err != nil {
		t.Fatalf("Failed to load test credential: %v", err)
	}

	jsonData, err := ToJSON(cred, true)
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	jsonStr := string(jsonData)

	// Check that secrets are shown
	if !strings.Contains(jsonStr, "\"pem\"") {
		t.Error("ToJSON(showSecrets=true) should include PEM field")
	}
	if !strings.Contains(jsonStr, "-----BEGIN PRIVATE KEY-----") {
		t.Error("ToJSON(showSecrets=true) should show private key in PEM format")
	}
	if strings.Contains(jsonStr, "(hidden)") {
		t.Error("ToJSON(showSecrets=true) should not hide any secrets")
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

func TestFormatRvVarName(t *testing.T) {
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
			got := formatRvVarName(tt.rvVar)
			if got != tt.want {
				t.Errorf("formatRvVarName(%v) = %s, want %s", tt.rvVar, got, tt.want)
			}
		})
	}
}

func TestFormatProtocolName(t *testing.T) {
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
			got := formatProtocolName(tt.proto)
			if got != tt.want {
				t.Errorf("formatProtocolName(%d) = %s, want %s", tt.proto, got, tt.want)
			}
		})
	}
}

func TestFormatMediumName(t *testing.T) {
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
			got := formatMediumName(tt.medium)
			if got != tt.want {
				t.Errorf("formatMediumName(%d) = %s, want %s", tt.medium, got, tt.want)
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

func TestFormatRvVarName_AllCases(t *testing.T) {
	tests := []struct {
		name     string
		variable protocol.RvVar
		expected string
	}{
		{"DevOnly", protocol.RVDevOnly, "DevOnly"},
		{"OwnerOnly", protocol.RVOwnerOnly, "OwnerOnly"},
		{"IPAddress", protocol.RVIPAddress, "IPAddress"},
		{"DevPort", protocol.RVDevPort, "DevPort"},
		{"OwnerPort", protocol.RVOwnerPort, "OwnerPort"},
		{"DNS", protocol.RVDns, "DNS"},
		{"SvCertHash", protocol.RVSvCertHash, "SvCertHash"},
		{"ClCertHash", protocol.RVClCertHash, "ClCertHash"},
		{"UserInput", protocol.RVUserInput, "UserInput"},
		{"WifiSsid", protocol.RVWifiSsid, "WifiSsid"},
		{"WifiPw", protocol.RVWifiPw, "WifiPw"},
		{"Medium", protocol.RVMedium, "Medium"},
		{"Protocol", protocol.RVProtocol, "Protocol"},
		{"Delaysec", protocol.RVDelaysec, "Delaysec"},
		{"Bypass", protocol.RVBypass, "Bypass"},
		{"ExtRV", protocol.RVExtRV, "ExtRV"},
		{"Unknown", protocol.RvVar(99), "Unknown(99)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatRvVarName(tt.variable)
			if result != tt.expected {
				t.Errorf("formatRvVarName(%d) = %s, want %s", tt.variable, result, tt.expected)
			}
		})
	}
}

func TestFormatRvValue_AdditionalCases(t *testing.T) {
	t.Run("Port with invalid CBOR", func(t *testing.T) {
		instr := protocol.RvInstruction{
			Variable: protocol.RVDevPort,
			Value:    []byte{0xff, 0xff}, // Invalid CBOR
		}
		result := formatRvValue(instr)
		if result == "" {
			t.Error("formatRvValue should handle invalid CBOR for ports")
		}
	})

	t.Run("DNS with raw bytes", func(t *testing.T) {
		instr := protocol.RvInstruction{
			Variable: protocol.RVDns,
			Value:    []byte("raw-dns"),
		}
		result := formatRvValue(instr)
		if result == "" {
			t.Error("formatRvValue(DNS) should handle raw bytes")
		}
	})

	t.Run("Protocol unknown value", func(t *testing.T) {
		protoValue, _ := cbor.Marshal(uint8(99))
		instr := protocol.RvInstruction{
			Variable: protocol.RVProtocol,
			Value:    protoValue,
		}
		result := formatRvValue(instr)
		if !strings.Contains(result, "Unknown") {
			t.Errorf("formatRvValue(Protocol) should handle unknown protocol, got %s", result)
		}
	})

	t.Run("Medium unknown value", func(t *testing.T) {
		mediumValue, _ := cbor.Marshal(uint8(99))
		instr := protocol.RvInstruction{
			Variable: protocol.RVMedium,
			Value:    mediumValue,
		}
		result := formatRvValue(instr)
		if !strings.Contains(result, "Unknown") {
			t.Errorf("formatRvValue(Medium) should handle unknown medium, got %s", result)
		}
	})

	t.Run("Delaysec with invalid CBOR", func(t *testing.T) {
		instr := protocol.RvInstruction{
			Variable: protocol.RVDelaysec,
			Value:    []byte{0xff}, // Invalid CBOR
		}
		result := formatRvValue(instr)
		if result == "" {
			t.Error("formatRvValue should handle invalid CBOR for delaysec")
		}
	})

	t.Run("Unknown variable with non-printable", func(t *testing.T) {
		instr := protocol.RvInstruction{
			Variable: protocol.RvVar(99),
			Value:    []byte{0x00, 0x01, 0x02, 0xff}, // Non-printable
		}
		result := formatRvValue(instr)
		if !strings.HasPrefix(result, "0x") {
			t.Errorf("formatRvValue should format non-printable as hex, got %s", result)
		}
	})

	t.Run("Unknown variable with printable", func(t *testing.T) {
		instr := protocol.RvInstruction{
			Variable: protocol.RvVar(99),
			Value:    []byte("printable text"),
		}
		result := formatRvValue(instr)
		if !strings.Contains(result, "printable") {
			t.Errorf("formatRvValue should show printable text, got %s", result)
		}
	})
}

func TestSaveToFile_ErrorCases(t *testing.T) {
	cred := createTestCredential(t)

	// Test with invalid path (directory that doesn't exist)
	err := SaveToFile(cred, "/nonexistent/directory/file.cbor")
	if err == nil {
		t.Error("SaveToFile should error when writing to invalid path")
	}
}

// Helper function to create a test credential
func createTestCredential(t *testing.T) *blob.DeviceCredential {
	// Generate a new ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Create public key hash
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(pubKeyBytes)

	// Generate GUID
	var guid protocol.GUID
	if _, err := rand.Read(guid[:]); err != nil {
		t.Fatal(err)
	}

	// Generate HMAC secret
	hmacSecret := make([]byte, 32)
	if _, err := rand.Read(hmacSecret); err != nil {
		t.Fatal(err)
	}

	// Create rendezvous info
	dnsValue, _ := cbor.Marshal("localhost")
	portValue, _ := cbor.Marshal(uint16(8080))
	protoValue, _ := cbor.Marshal(uint8(2)) // HTTPS

	rvInfo := [][]protocol.RvInstruction{
		{
			{Variable: protocol.RVDns, Value: dnsValue},
			{Variable: protocol.RVDevPort, Value: portValue},
			{Variable: protocol.RVProtocol, Value: protoValue},
		},
	}

	return &blob.DeviceCredential{
		Active: true,
		DeviceCredential: fdo.DeviceCredential{
			Version:    101, // 1.1
			DeviceInfo: "Test Device",
			GUID:       guid,
			RvInfo:     rvInfo,
			PublicKeyHash: protocol.Hash{
				Algorithm: protocol.Sha256Hash,
				Value:     hash[:],
			},
		},
		HmacSecret: hmacSecret,
		PrivateKey: blob.Pkcs8Key{Signer: privateKey},
	}
}
