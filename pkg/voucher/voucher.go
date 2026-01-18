package voucher

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// LoadFromFile loads an ownership voucher from a PEM-encoded file
func LoadFromFile(path string) (*fdo.Voucher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "OWNERSHIP VOUCHER" {
		return nil, fmt.Errorf("invalid PEM block type: %s (expected OWNERSHIP VOUCHER)", block.Type)
	}

	// Unmarshal CBOR data from PEM block bytes
	var voucher fdo.Voucher
	if err := cbor.Unmarshal(block.Bytes, &voucher); err != nil {
		return nil, fmt.Errorf("failed to unmarshal voucher: %w", err)
	}

	return &voucher, nil
}

// SaveToFile saves an ownership voucher to a PEM-encoded file
func SaveToFile(voucher *fdo.Voucher, path string) error {
	// Marshal voucher to CBOR
	cborData, err := cbor.Marshal(voucher)
	if err != nil {
		return fmt.Errorf("failed to marshal voucher: %w", err)
	}

	// Create PEM block
	block := &pem.Block{
		Type:  "OWNERSHIP VOUCHER",
		Bytes: cborData,
	}

	// Encode PEM block
	pemData := pem.EncodeToMemory(block)
	if pemData == nil {
		return fmt.Errorf("failed to encode PEM block")
	}

	// Write to file
	if err := os.WriteFile(path, pemData, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// ToPEM converts a voucher to PEM-encoded bytes
func ToPEM(voucher *fdo.Voucher) ([]byte, error) {
	// Marshal voucher to CBOR
	cborData, err := cbor.Marshal(voucher)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal voucher: %w", err)
	}

	// Create PEM block
	block := &pem.Block{
		Type:  "OWNERSHIP VOUCHER",
		Bytes: cborData,
	}

	// Encode PEM block
	pemData := pem.EncodeToMemory(block)
	if pemData == nil {
		return nil, fmt.Errorf("failed to encode PEM block")
	}

	return pemData, nil
}

// LoadPrivateKeyFromFile loads a private key from a PEM-encoded or DER-encoded file
// Supports ECDSA and RSA private keys
func LoadPrivateKeyFromFile(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Try to decode as PEM first
	block, _ := pem.Decode(data)

	var keyBytes []byte
	var keyType string

	if block != nil {
		// PEM format
		keyBytes = block.Bytes
		keyType = block.Type
	} else {
		// Assume DER format (raw binary)
		keyBytes = data
		keyType = "DER"
	}

	// Try to parse as EC private key
	if keyType == "EC PRIVATE KEY" || keyType == "DER" {
		key, err := x509.ParseECPrivateKey(keyBytes)
		if err == nil {
			return key, nil
		}
		// If not EC key and it's DER, continue trying other formats
		if keyType == "EC PRIVATE KEY" {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
	}

	// Try to parse as PKCS8 private key (supports both ECDSA and RSA)
	if keyType == "PRIVATE KEY" || keyType == "DER" {
		key, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err == nil {
			switch k := key.(type) {
			case *ecdsa.PrivateKey:
				return k, nil
			case *rsa.PrivateKey:
				return k, nil
			default:
				return nil, fmt.Errorf("unsupported key type in PKCS8: %T", key)
			}
		}
		// If not PKCS8 and it's specified as PRIVATE KEY, return error
		if keyType == "PRIVATE KEY" {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
	}

	// Try to parse as RSA private key (PKCS1)
	if keyType == "RSA PRIVATE KEY" || keyType == "DER" {
		key, err := x509.ParsePKCS1PrivateKey(keyBytes)
		if err == nil {
			return key, nil
		}
		// If not RSA PKCS1 and it's specified as RSA PRIVATE KEY, return error
		if keyType == "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
	}

	// If we got here with DER format, we couldn't parse it
	if keyType == "DER" {
		return nil, fmt.Errorf("failed to parse DER key: tried EC, PKCS8, and PKCS1 RSA formats")
	}

	return nil, fmt.Errorf("unsupported PEM block type: %s", keyType)
}

// LoadPublicKeyOrCertFromFile loads a public key or certificate from a PEM-encoded file
// Returns either a public key (*ecdsa.PublicKey or *rsa.PublicKey) or a certificate chain
func LoadPublicKeyOrCertFromFile(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to decode all PEM blocks
	var certs []*x509.Certificate
	rest := data
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		// Try to parse as certificate
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
			continue
		}

		// Try to parse as public key
		if block.Type == "PUBLIC KEY" {
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}

			switch pubKey := key.(type) {
			case *ecdsa.PublicKey:
				return pubKey, nil
			case *rsa.PublicKey:
				return pubKey, nil
			default:
				return nil, fmt.Errorf("unsupported public key type: %T", key)
			}
		}
	}

	// If we found certificates, return them as a chain
	if len(certs) > 0 {
		return certs, nil
	}

	return nil, fmt.Errorf("no valid public key or certificate found in file")
}

// Extend extends a voucher with a new owner's public key or certificate
func Extend(voucher *fdo.Voucher, ownerKey crypto.Signer, nextOwner interface{}) (*fdo.Voucher, error) {
	// Call the appropriate ExtendVoucher function based on nextOwner type
	switch next := nextOwner.(type) {
	case *ecdsa.PublicKey:
		return fdo.ExtendVoucher(voucher, ownerKey, next, nil)
	case *rsa.PublicKey:
		return fdo.ExtendVoucher(voucher, ownerKey, next, nil)
	case []*x509.Certificate:
		return fdo.ExtendVoucher(voucher, ownerKey, next, nil)
	default:
		return nil, fmt.Errorf("unsupported next owner type: %T (must be *ecdsa.PublicKey, *rsa.PublicKey, or []*x509.Certificate)", nextOwner)
	}
}

// formatRvInstruction formats a single RvInstruction in human-readable format
func formatRvInstruction(instr protocol.RvInstruction) map[string]interface{} {
	varName := getRvVarName(instr.Variable)
	var value interface{}

	// Decode value based on variable type
	switch instr.Variable {
	case protocol.RVIPAddress:
		// Try to unmarshal as CBOR byte string
		var ipBytes []byte
		if err := cbor.Unmarshal(instr.Value, &ipBytes); err == nil {
			ip := net.IP(ipBytes)
			value = ip.String()
		} else if len(instr.Value) >= 4 {
			ip := net.IP(instr.Value)
			value = ip.String()
		} else {
			value = fmt.Sprintf("0x%x", instr.Value)
		}
	case protocol.RVDevPort, protocol.RVOwnerPort:
		// Try to unmarshal as CBOR uint16
		var port uint16
		if err := cbor.Unmarshal(instr.Value, &port); err == nil {
			value = port
		} else if len(instr.Value) == 2 {
			port = binary.BigEndian.Uint16(instr.Value)
			value = port
		} else {
			value = fmt.Sprintf("%v", instr.Value)
		}
	case protocol.RVDns:
		// Try to unmarshal as CBOR string
		var dns string
		if err := cbor.Unmarshal(instr.Value, &dns); err == nil {
			value = dns
		} else {
			value = string(instr.Value)
		}
	case protocol.RVProtocol:
		// Try to unmarshal as CBOR uint8
		var proto uint8
		if err := cbor.Unmarshal(instr.Value, &proto); err == nil {
			value = getProtocolName(proto)
		} else if len(instr.Value) == 1 {
			value = getProtocolName(instr.Value[0])
		} else {
			value = fmt.Sprintf("%v", instr.Value)
		}
	case protocol.RVMedium:
		// Try to unmarshal as CBOR uint8
		var medium uint8
		if err := cbor.Unmarshal(instr.Value, &medium); err == nil {
			value = getMediumName(medium)
		} else if len(instr.Value) == 1 {
			value = getMediumName(instr.Value[0])
		} else {
			value = fmt.Sprintf("%v", instr.Value)
		}
	case protocol.RVDelaysec:
		// Try to unmarshal as CBOR uint16
		var delay uint16
		if err := cbor.Unmarshal(instr.Value, &delay); err == nil {
			value = fmt.Sprintf("%d seconds", delay)
		} else if len(instr.Value) == 2 {
			delay = binary.BigEndian.Uint16(instr.Value)
			value = fmt.Sprintf("%d seconds", delay)
		} else {
			value = fmt.Sprintf("%v", instr.Value)
		}
	default:
		// For other types, show as hex or string if printable
		if isPrintable(instr.Value) {
			value = string(instr.Value)
		} else {
			value = fmt.Sprintf("0x%x", instr.Value)
		}
	}

	return map[string]interface{}{
		varName: value,
	}
}

// getRvVarName returns the human-readable name for an RvVar
func getRvVarName(v protocol.RvVar) string {
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

// getProtocolName returns the human-readable name for a protocol
func getProtocolName(p uint8) string {
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

// getMediumName returns the human-readable name for a medium
func getMediumName(m uint8) string {
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

// formatCertificate extracts and formats certificate information
func formatCertificate(certWrapper *cbor.X509Certificate) map[string]interface{} {
	// X509Certificate is a type alias for x509.Certificate
	cert := (*x509.Certificate)(certWrapper)

	return map[string]interface{}{
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"notBefore":    cert.NotBefore.Format("2006-01-02 15:04:05 MST"),
		"notAfter":     cert.NotAfter.Format("2006-01-02 15:04:05 MST"),
		"serialNumber": cert.SerialNumber.String(),
	}
}

// formatPublicKey formats a protocol.PublicKey
func formatPublicKey(pk protocol.PublicKey) map[string]interface{} {
	// Convert DER to PEM format
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pk.Body,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	return map[string]interface{}{
		"type":      pk.Type.String(),
		"publicKey": string(pemData),
	}
}

// formatHmac formats a protocol.Hmac
func formatHmac(hmac protocol.Hmac) map[string]interface{} {
	return map[string]interface{}{
		"algorithm": hmac.Algorithm.String(),
		"value":     fmt.Sprintf("0x%x", hmac.Value),
	}
}

// formatHash formats a protocol.Hash
func formatHash(hash protocol.Hash) map[string]interface{} {
	return map[string]interface{}{
		"algorithm": hash.Algorithm.String(),
		"value":     fmt.Sprintf("0x%x", hash.Value),
	}
}

// ToText converts a voucher to a human-friendly text representation
func ToText(voucher *fdo.Voucher) string {
	var output string

	// Header section
	output += "OWNERSHIP VOUCHER\n"
	output += "=================\n\n"

	output += fmt.Sprintf("Protocol Version: %s\n", formatVersion(voucher.Version))
	output += fmt.Sprintf("GUID: %x\n", voucher.Header.Val.GUID)
	output += fmt.Sprintf("Device Info: %s\n\n", voucher.Header.Val.DeviceInfo)

	// Manufacturer Key
	output += "Manufacturer Public Key:\n"
	output += fmt.Sprintf("  Type: %s\n", voucher.Header.Val.ManufacturerKey.Type.String())
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: voucher.Header.Val.ManufacturerKey.Body,
	}
	pemData := pem.EncodeToMemory(pemBlock)
	for _, line := range splitLines(string(pemData)) {
		output += "  " + line + "\n"
	}
	output += "\n"

	// Header HMAC
	output += "Header HMAC:\n"
	output += fmt.Sprintf("  Algorithm: %s\n", voucher.Hmac.Algorithm.String())
	output += fmt.Sprintf("  Value: %x\n\n", voucher.Hmac.Value)

	// Device Certificate Chain Hash
	if voucher.Header.Val.CertChainHash != nil {
		output += "Device Certificate Chain Hash:\n"
		output += fmt.Sprintf("  Algorithm: %s\n", voucher.Header.Val.CertChainHash.Algorithm.String())
		output += fmt.Sprintf("  Value: %x\n\n", voucher.Header.Val.CertChainHash.Value)
	}

	// Rendezvous Info
	output += "Rendezvous Information:\n"
	for i, rvList := range voucher.Header.Val.RvInfo {
		output += fmt.Sprintf("  Directive %d:\n", i+1)
		for _, instr := range rvList {
			varName := getRvVarName(instr.Variable)
			value := formatRvValue(instr)
			output += fmt.Sprintf("    %s: %s\n", varName, value)
		}
	}
	output += "\n"

	// Device Certificate Chain
	if voucher.CertChain != nil && len(*voucher.CertChain) > 0 {
		output += fmt.Sprintf("Device Certificate Chain (%d certificates):\n", len(*voucher.CertChain))
		for i, certWrapper := range *voucher.CertChain {
			cert := (*x509.Certificate)(certWrapper)
			output += fmt.Sprintf("  Certificate %d:\n", i+1)
			output += fmt.Sprintf("    Subject: %s\n", cert.Subject.String())
			output += fmt.Sprintf("    Issuer: %s\n", cert.Issuer.String())
			output += fmt.Sprintf("    Valid From: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
			output += fmt.Sprintf("    Valid Until: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
			output += fmt.Sprintf("    Serial Number: %s\n", cert.SerialNumber.String())
		}
		output += "\n"
	}

	// Ownership Entries
	if len(voucher.Entries) > 0 {
		output += fmt.Sprintf("Ownership Entries (%d transfers):\n", len(voucher.Entries))
		for i, entry := range voucher.Entries {
			output += fmt.Sprintf("  Entry %d:\n", i+1)
			output += fmt.Sprintf("    Previous Hash: %x\n", entry.Payload.Val.PreviousHash.Value)
			output += fmt.Sprintf("    Header Hash: %x\n", entry.Payload.Val.HeaderHash.Value)
			output += fmt.Sprintf("    Owner Public Key Type: %s\n", entry.Payload.Val.PublicKey.Type.String())

			pemBlock := &pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: entry.Payload.Val.PublicKey.Body,
			}
			pemData := pem.EncodeToMemory(pemBlock)
			for _, line := range splitLines(string(pemData)) {
				output += "    " + line + "\n"
			}
		}
	} else {
		output += "Ownership Entries: None (manufacturer voucher)\n"
	}

	return output
}

// formatVersion formats a protocol version as major.minor
func formatVersion(version uint16) string {
	major := version / 100
	minor := version % 100
	return fmt.Sprintf("%d.%d", major, minor)
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

// formatRvValue formats a rendezvous instruction value for text output
func formatRvValue(instr protocol.RvInstruction) string {
	switch instr.Variable {
	case protocol.RVIPAddress:
		var ipBytes []byte
		if err := cbor.Unmarshal(instr.Value, &ipBytes); err == nil {
			ip := net.IP(ipBytes)
			return ip.String()
		}
		return fmt.Sprintf("0x%x", instr.Value)
	case protocol.RVDevPort, protocol.RVOwnerPort:
		var port uint16
		if err := cbor.Unmarshal(instr.Value, &port); err == nil {
			return fmt.Sprintf("%d", port)
		}
		return fmt.Sprintf("%v", instr.Value)
	case protocol.RVDns:
		// Try to unmarshal as CBOR string
		var dns string
		if err := cbor.Unmarshal(instr.Value, &dns); err == nil {
			return dns
		}
		return string(instr.Value)
	case protocol.RVProtocol:
		var proto uint8
		if err := cbor.Unmarshal(instr.Value, &proto); err == nil {
			return getProtocolName(proto)
		}
		return fmt.Sprintf("%v", instr.Value)
	case protocol.RVMedium:
		var medium uint8
		if err := cbor.Unmarshal(instr.Value, &medium); err == nil {
			return getMediumName(medium)
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

// ToJSON converts a voucher to a JSON representation for display
func ToJSON(voucher *fdo.Voucher) ([]byte, error) {
	// Format rvInfo in human-readable format
	var formattedRvInfo [][]map[string]interface{}
	for _, rvList := range voucher.Header.Val.RvInfo {
		var formattedList []map[string]interface{}
		for _, instr := range rvList {
			formattedList = append(formattedList, formatRvInstruction(instr))
		}
		formattedRvInfo = append(formattedRvInfo, formattedList)
	}

	// Build header object
	headerInfo := map[string]interface{}{
		"version":         formatVersion(voucher.Header.Val.Version),
		"guid":            fmt.Sprintf("%x", voucher.Header.Val.GUID),
		"deviceInfo":      voucher.Header.Val.DeviceInfo,
		"rvInfo":          formattedRvInfo,
		"manufacturerKey": formatPublicKey(voucher.Header.Val.ManufacturerKey),
	}

	// Add cert chain hash if present
	if voucher.Header.Val.CertChainHash != nil {
		headerInfo["devCertChainHash"] = formatHash(*voucher.Header.Val.CertChainHash)
	}

	// Create a simplified representation for display
	display := map[string]interface{}{
		"version":    formatVersion(voucher.Version),
		"header":     headerInfo,
		"headerHmac": formatHmac(voucher.Hmac),
	}

	// Add certificate chain details if present
	if voucher.CertChain != nil && len(*voucher.CertChain) > 0 {
		var certDetails []map[string]interface{}
		for _, certWrapper := range *voucher.CertChain {
			certInfo := formatCertificate(certWrapper)
			certDetails = append(certDetails, certInfo)
		}
		display["deviceCertificateChain"] = certDetails
	}

	// Add entries
	if len(voucher.Entries) > 0 {
		var entriesDetails []map[string]interface{}
		for i, entry := range voucher.Entries {
			entryInfo := map[string]interface{}{
				"index":        i,
				"previousHash": formatHash(entry.Payload.Val.PreviousHash),
				"headerHash":   formatHash(entry.Payload.Val.HeaderHash),
				"publicKey":    formatPublicKey(entry.Payload.Val.PublicKey),
			}

			// Add extra info if present
			if entry.Payload.Val.Extra != nil {
				entryInfo["extra"] = "present"
			}

			entriesDetails = append(entriesDetails, entryInfo)
		}
		display["entries"] = entriesDetails
	} else {
		display["entries"] = []interface{}{}
	}

	return json.MarshalIndent(display, "", "  ")
}

// VerifyOptions contains optional parameters for voucher verification
type VerifyOptions struct {
	HmacSecret    []byte          // Optional: for header HMAC verification
	PublicKeyHash *protocol.Hash  // Optional: for manufacturer key hash verification
	TrustedRoots  *x509.CertPool  // Optional: for certificate chain verification
}

// VerifyCheck represents the result of a single verification check
type VerifyCheck struct {
	Name   string
	Passed bool
	Error  error
}

// VerifyResult contains the overall verification result
type VerifyResult struct {
	Passed bool
	Checks []VerifyCheck
}

// Verify performs verification checks on a voucher
// It always runs basic checks (entries, cert chain hash, etc.)
// and runs additional checks if secrets are provided in opts
func Verify(voucher *fdo.Voucher, opts *VerifyOptions) *VerifyResult {
	if opts == nil {
		opts = &VerifyOptions{}
	}

	result := &VerifyResult{
		Passed: true,
		Checks: []VerifyCheck{},
	}

	// Check 1: Verify ownership entries (cryptographic signatures)
	checkResult := VerifyCheck{Name: "Ownership Entries"}
	if err := voucher.VerifyEntries(); err != nil {
		checkResult.Passed = false
		checkResult.Error = err
		result.Passed = false
	} else {
		checkResult.Passed = true
	}
	result.Checks = append(result.Checks, checkResult)

	// Check 2: Verify certificate chain hash (if present)
	checkResult = VerifyCheck{Name: "Certificate Chain Hash"}
	if voucher.Header.Val.CertChainHash != nil {
		if err := voucher.VerifyCertChainHash(); err != nil {
			checkResult.Passed = false
			checkResult.Error = err
			result.Passed = false
		} else {
			checkResult.Passed = true
		}
		result.Checks = append(result.Checks, checkResult)
	}

	// Check 3: Verify device certificate chain (self-signed if no trusted roots)
	if voucher.CertChain != nil && len(*voucher.CertChain) > 0 {
		checkResult = VerifyCheck{Name: "Device Certificate Chain"}
		if opts.TrustedRoots != nil {
			if err := voucher.VerifyDeviceCertChain(opts.TrustedRoots); err != nil {
				checkResult.Passed = false
				checkResult.Error = err
				result.Passed = false
			} else {
				checkResult.Passed = true
			}
		} else {
			// Verify with nil roots (self-signed trust)
			if err := voucher.VerifyDeviceCertChain(nil); err != nil {
				checkResult.Passed = false
				checkResult.Error = err
				result.Passed = false
			} else {
				checkResult.Passed = true
			}
		}
		result.Checks = append(result.Checks, checkResult)
	}

	// Check 4: Verify manufacturer certificate chain
	checkResult = VerifyCheck{Name: "Manufacturer Certificate Chain"}
	if opts.TrustedRoots != nil {
		if err := voucher.VerifyManufacturerCertChain(opts.TrustedRoots); err != nil {
			checkResult.Passed = false
			checkResult.Error = err
			result.Passed = false
		} else {
			checkResult.Passed = true
		}
	} else {
		// Verify with nil roots (self-signed trust)
		if err := voucher.VerifyManufacturerCertChain(nil); err != nil {
			checkResult.Passed = false
			checkResult.Error = err
			result.Passed = false
		} else {
			checkResult.Passed = true
		}
	}
	result.Checks = append(result.Checks, checkResult)

	// Check 5: Verify header HMAC (if HMAC secret provided)
	if len(opts.HmacSecret) > 0 {
		checkResult = VerifyCheck{Name: "Header HMAC"}
		// Create HMAC hash instances with the provided secret
		hmacSha256 := hmac.New(sha256.New, opts.HmacSecret)
		hmacSha384 := hmac.New(sha512.New384, opts.HmacSecret)
		if err := voucher.VerifyHeader(hmacSha256, hmacSha384); err != nil {
			checkResult.Passed = false
			checkResult.Error = err
			result.Passed = false
		} else {
			checkResult.Passed = true
		}
		result.Checks = append(result.Checks, checkResult)
	}

	// Check 6: Verify manufacturer key hash (if public key hash provided)
	if opts.PublicKeyHash != nil {
		checkResult = VerifyCheck{Name: "Manufacturer Key Hash"}
		if err := voucher.VerifyManufacturerKey(*opts.PublicKeyHash); err != nil {
			checkResult.Passed = false
			checkResult.Error = err
			result.Passed = false
		} else {
			checkResult.Passed = true
		}
		result.Checks = append(result.Checks, checkResult)
	}

	return result
}

// LoadDeviceCredentialFromFile loads a device credential from a CBOR file
func LoadDeviceCredentialFromFile(path string) (*blob.DeviceCredential, error) {
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

// ParseHmacSecret parses an HMAC secret from a hex string
func ParseHmacSecret(hexStr string) ([]byte, error) {
	// Remove common prefixes
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")
	hexStr = strings.TrimSpace(hexStr)

	secret, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	return secret, nil
}

// LoadHmacSecretFromFile loads an HMAC secret from a file
// Tries to parse as hex first, then falls back to raw binary
func LoadHmacSecretFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// Try to parse as hex first
	hexStr := strings.TrimSpace(string(data))
	secret, err := ParseHmacSecret(hexStr)
	if err == nil {
		return secret, nil
	}

	// Fall back to raw binary
	return data, nil
}

// ParsePublicKeyHash parses a public key hash from a hex string with algorithm
func ParsePublicKeyHash(algorithm string, hexStr string) (*protocol.Hash, error) {
	// Remove common prefixes
	hexStr = strings.TrimPrefix(hexStr, "0x")
	hexStr = strings.TrimPrefix(hexStr, "0X")
	hexStr = strings.TrimSpace(hexStr)

	hashValue, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Parse algorithm
	var algo protocol.HashAlg
	switch strings.ToUpper(algorithm) {
	case "SHA256", "SHA-256":
		algo = protocol.Sha256Hash
	case "SHA384", "SHA-384":
		algo = protocol.Sha384Hash
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s (supported: SHA256, SHA384)", algorithm)
	}

	return &protocol.Hash{
		Algorithm: algo,
		Value:     hashValue,
	}, nil
}

// LoadPublicKeyHashFromFile loads a public key hash from a file
// Expects format: "ALGORITHM:HEXVALUE" (e.g., "SHA256:abcd1234...")
func LoadPublicKeyHashFromFile(path string) (*protocol.Hash, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	content := strings.TrimSpace(string(data))
	parts := strings.SplitN(content, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid format: expected 'ALGORITHM:HEXVALUE'")
	}

	return ParsePublicKeyHash(parts[0], parts[1])
}

// LoadCACertsFromFile loads CA certificates from a PEM file
func LoadCACertsFromFile(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	pool := x509.NewCertPool()
	rest := data
	count := 0

	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		pool.AddCert(cert)
		count++
	}

	if count == 0 {
		return nil, fmt.Errorf("no certificates found in file")
	}

	return pool, nil
}
