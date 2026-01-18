package credential

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// LoadFromFile loads a device credential from a CBOR file
func LoadFromFile(path string) (*blob.DeviceCredential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var cred blob.DeviceCredential
	if err := cbor.Unmarshal(data, &cred); err != nil {
		return nil, fmt.Errorf("failed to unmarshal device credential: %w", err)
	}

	return &cred, nil
}

// SaveToFile saves a device credential to a CBOR file
func SaveToFile(cred *blob.DeviceCredential, path string) error {
	data, err := cbor.Marshal(cred)
	if err != nil {
		return fmt.Errorf("failed to marshal device credential: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// formatVersion formats a protocol version as major.minor
func formatVersion(version uint16) string {
	major := version / 100
	minor := version % 100
	return fmt.Sprintf("%d.%d", major, minor)
}

// formatRvInstruction formats a single RvInstruction for text output
func formatRvInstruction(instr protocol.RvInstruction) string {
	varName := formatRvVarName(instr.Variable)
	value := formatRvValue(instr)
	return fmt.Sprintf("    %s: %s", varName, value)
}

// formatRvVarName returns the human-readable name for an RvVar
func formatRvVarName(v protocol.RvVar) string {
	switch v {
	case protocol.RVDevOnly:
		return "DevOnly"
	case protocol.RVOwnerOnly:
		return "OwnerOnly"
	case protocol.RVIPAddress:
		return "IPAddress"
	case protocol.RVDevPort:
		return "DevPort"
	case protocol.RVOwnerPort:
		return "OwnerPort"
	case protocol.RVDns:
		return "DNS"
	case protocol.RVSvCertHash:
		return "SvCertHash"
	case protocol.RVClCertHash:
		return "ClCertHash"
	case protocol.RVUserInput:
		return "UserInput"
	case protocol.RVWifiSsid:
		return "WifiSsid"
	case protocol.RVWifiPw:
		return "WifiPw"
	case protocol.RVMedium:
		return "Medium"
	case protocol.RVProtocol:
		return "Protocol"
	case protocol.RVDelaysec:
		return "Delaysec"
	case protocol.RVBypass:
		return "Bypass"
	case protocol.RVExtRV:
		return "ExtRV"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

// formatRvValue formats a rendezvous instruction value
func formatRvValue(instr protocol.RvInstruction) string {
	switch instr.Variable {
	case protocol.RVIPAddress:
		var ipBytes []byte
		if err := cbor.Unmarshal(instr.Value, &ipBytes); err == nil {
			return fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])
		}
		return fmt.Sprintf("0x%x", instr.Value)
	case protocol.RVDevPort, protocol.RVOwnerPort:
		var port uint16
		if err := cbor.Unmarshal(instr.Value, &port); err == nil {
			return fmt.Sprintf("%d", port)
		}
		return fmt.Sprintf("%v", instr.Value)
	case protocol.RVDns:
		var dns string
		if err := cbor.Unmarshal(instr.Value, &dns); err == nil {
			return dns
		}
		return string(instr.Value)
	case protocol.RVProtocol:
		var proto uint8
		if err := cbor.Unmarshal(instr.Value, &proto); err == nil {
			return formatProtocolName(proto)
		}
		return fmt.Sprintf("%v", instr.Value)
	case protocol.RVMedium:
		var medium uint8
		if err := cbor.Unmarshal(instr.Value, &medium); err == nil {
			return formatMediumName(medium)
		}
		return fmt.Sprintf("%v", instr.Value)
	case protocol.RVDelaysec:
		var delay uint16
		if err := cbor.Unmarshal(instr.Value, &delay); err == nil {
			return fmt.Sprintf("%d seconds", delay)
		}
		return fmt.Sprintf("%v", instr.Value)
	default:
		if isPrintable(instr.Value) {
			return string(instr.Value)
		}
		return fmt.Sprintf("0x%x", instr.Value)
	}
}

// formatProtocolName returns the human-readable name for a protocol
func formatProtocolName(p uint8) string {
	switch p {
	case 0:
		return "REST"
	case 1:
		return "HTTP"
	case 2:
		return "HTTPS"
	case 3:
		return "TCP"
	case 4:
		return "TLS"
	case 5:
		return "CoAP-TCP"
	case 6:
		return "CoAP-UDP"
	default:
		return fmt.Sprintf("Unknown(%d)", p)
	}
}

// formatMediumName returns the human-readable name for a medium
func formatMediumName(m uint8) string {
	switch m {
	case 20:
		return "Ethernet"
	case 21:
		return "WiFi"
	default:
		return fmt.Sprintf("Unknown(%d)", m)
	}
}

// isPrintable checks if a byte slice contains only printable ASCII characters
func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 32 || c > 126 {
			return false
		}
	}
	return len(b) > 0
}

// getPrivateKeyInfo extracts information about the private key
func getPrivateKeyInfo(pkcs8Key blob.Pkcs8Key) map[string]string {
	info := make(map[string]string)

	if !pkcs8Key.IsValid() {
		return info
	}

	// Get the underlying signer
	signer := pkcs8Key.Signer
	if signer == nil {
		return info
	}

	// Determine key type and details
	switch key := signer.(type) {
	case *ecdsa.PrivateKey:
		info["type"] = "ECDSA"
		info["curve"] = key.Curve.Params().Name
		info["bits"] = fmt.Sprintf("%d", key.Curve.Params().BitSize)
	case *rsa.PrivateKey:
		info["type"] = "RSA"
		info["bits"] = fmt.Sprintf("%d", key.N.BitLen())
	default:
		info["type"] = "Unknown"
	}

	return info
}

// privateKeyToPEM converts a private key to PEM format
func privateKeyToPEM(pkcs8Key blob.Pkcs8Key) (string, error) {
	if !pkcs8Key.IsValid() {
		return "", fmt.Errorf("invalid private key")
	}

	signer := pkcs8Key.Signer
	if signer == nil {
		return "", fmt.Errorf("nil signer")
	}

	// Marshal to PKCS#8 DER format
	derBytes, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Create PEM block
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}

	// Encode to PEM
	pemData := pem.EncodeToMemory(pemBlock)
	return string(pemData), nil
}

// ToText converts a device credential to a human-friendly text representation
// If showSecrets is true, the full private key in PEM format will be included
func ToText(cred *blob.DeviceCredential, showSecrets bool) string {
	var output string

	// Header section
	output += "DEVICE CREDENTIAL\n"
	output += "=================\n\n"

	output += fmt.Sprintf("Active: %t\n", cred.Active)
	output += fmt.Sprintf("Protocol Version: %s\n", formatVersion(cred.Version))
	output += fmt.Sprintf("GUID: %x\n", cred.GUID)
	output += fmt.Sprintf("Device Info: %s\n\n", cred.DeviceInfo)

	// Public Key Hash
	output += "Public Key Hash:\n"
	output += fmt.Sprintf("  Algorithm: %s\n", cred.PublicKeyHash.Algorithm.String())
	output += fmt.Sprintf("  Value: %x\n\n", cred.PublicKeyHash.Value)

	// HMAC Secret
	if len(cred.HmacSecret) > 0 {
		output += "HMAC Secret:\n"
		output += fmt.Sprintf("  Length: %d bytes\n", len(cred.HmacSecret))
		if showSecrets {
			output += fmt.Sprintf("  Value: %x\n\n", cred.HmacSecret)
		} else {
			output += "  Value: (hidden, use --show-secrets to display)\n\n"
		}
	}

	// Private Key
	if cred.PrivateKey.IsValid() {
		output += "Private Key:\n"
		keyInfo := getPrivateKeyInfo(cred.PrivateKey)
		if keyType, ok := keyInfo["type"]; ok {
			output += fmt.Sprintf("  Type: %s\n", keyType)
		}
		if bits, ok := keyInfo["bits"]; ok {
			output += fmt.Sprintf("  Size: %s bits\n", bits)
		}
		if curve, ok := keyInfo["curve"]; ok {
			output += fmt.Sprintf("  Curve: %s\n", curve)
		}
		output += "  Encoding: PKCS#8\n"

		if showSecrets {
			pemKey, err := privateKeyToPEM(cred.PrivateKey)
			if err == nil {
				output += "\n  PEM Format:\n"
				for _, line := range splitLines(pemKey) {
					output += "  " + line + "\n"
				}
			} else {
				output += fmt.Sprintf("  (failed to export PEM: %v)\n", err)
			}
		} else {
			output += "  (use --show-secrets to display full key)\n"
		}
		output += "\n"
	}

	// Rendezvous Info
	output += "Rendezvous Information:\n"
	for i, rvList := range cred.RvInfo {
		output += fmt.Sprintf("  Directive %d:\n", i+1)
		for _, instr := range rvList {
			output += formatRvInstruction(instr) + "\n"
		}
	}

	return output
}

// splitLines splits a string into lines
func splitLines(s string) []string {
	lines := []string{}
	current := ""
	for _, ch := range s {
		if ch == '\n' {
			if current != "" {
				lines = append(lines, current)
			}
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

// ToJSON converts a device credential to a JSON representation
// If showSecrets is true, the full private key in PEM format will be included
func ToJSON(cred *blob.DeviceCredential, showSecrets bool) ([]byte, error) {
	// Format rvInfo in human-readable format
	var formattedRvInfo [][]map[string]any
	for _, rvList := range cred.RvInfo {
		var formattedList []map[string]any
		for _, instr := range rvList {
			varName := formatRvVarName(instr.Variable)
			value := formatRvValue(instr)
			formattedList = append(formattedList, map[string]any{
				varName: value,
			})
		}
		formattedRvInfo = append(formattedRvInfo, formattedList)
	}

	display := map[string]any{
		"active":     cred.Active,
		"version":    formatVersion(cred.Version),
		"guid":       fmt.Sprintf("%x", cred.GUID),
		"deviceInfo": cred.DeviceInfo,
		"rvInfo":     formattedRvInfo,
		"publicKeyHash": map[string]any{
			"algorithm": cred.PublicKeyHash.Algorithm.String(),
			"value":     fmt.Sprintf("%x", cred.PublicKeyHash.Value),
		},
	}

	// Add HMAC secret if present
	if len(cred.HmacSecret) > 0 {
		hmacData := map[string]any{
			"length": len(cred.HmacSecret),
		}
		if showSecrets {
			hmacData["value"] = fmt.Sprintf("%x", cred.HmacSecret)
		} else {
			hmacData["value"] = "(hidden)"
		}
		display["hmacSecret"] = hmacData
	}

	// Add private key info if present
	if cred.PrivateKey.IsValid() {
		keyInfo := getPrivateKeyInfo(cred.PrivateKey)
		pkData := map[string]any{
			"present":  true,
			"encoding": "PKCS#8",
		}
		if keyType, ok := keyInfo["type"]; ok {
			pkData["type"] = keyType
		}
		if bits, ok := keyInfo["bits"]; ok {
			pkData["bits"] = bits
		}
		if curve, ok := keyInfo["curve"]; ok {
			pkData["curve"] = curve
		}

		if showSecrets {
			pemKey, err := privateKeyToPEM(cred.PrivateKey)
			if err == nil {
				pkData["pem"] = pemKey
			}
		}

		display["privateKey"] = pkData
	}

	return json.MarshalIndent(display, "", "  ")
}
