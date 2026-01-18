//go:build ignore
// +build ignore

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/blob"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

func main() {
	// Generate a new ECDSA key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate key: %v\n", err)
		os.Exit(1)
	}

	// Create public key hash
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal public key: %v\n", err)
		os.Exit(1)
	}
	hash := sha256.Sum256(pubKeyBytes)

	// Generate GUID
	var guid protocol.GUID
	if _, err := rand.Read(guid[:]); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate GUID: %v\n", err)
		os.Exit(1)
	}

	// Generate HMAC secret
	hmacSecret := make([]byte, 32)
	if _, err := rand.Read(hmacSecret); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate HMAC secret: %v\n", err)
		os.Exit(1)
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

	// Create device credential
	cred := blob.DeviceCredential{
		Active: true,
		DeviceCredential: fdo.DeviceCredential{
			Version:    101, // 1.1
			DeviceInfo: "Example Device",
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

	// Marshal to CBOR
	data, err := cbor.Marshal(cred)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal credential: %v\n", err)
		os.Exit(1)
	}

	// Write to file
	if err := os.WriteFile("example/device_credential.cbor", data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write file: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Device credential created at example/device_credential.cbor")
}
