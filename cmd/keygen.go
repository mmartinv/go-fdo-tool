package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mmartinv/go-fdo-tool/pkg/keygen"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new manufacturer or owner private key",
	Long: `Generate a new private key for use as a manufacturer or owner key in FDO.

Supported key types (matching FDO protocol specifications):
  - ecdsa-p256: ECDSA with NIST P-256 curve (secp256r1, prime256v1)
  - ecdsa-p384: ECDSA with NIST P-384 curve (secp384r1) - Recommended
  - rsa-2048:   RSA with 2048-bit key
  - rsa-3072:   RSA with 3072-bit key
  - rsa-4096:   RSA with 4096-bit key

The generated keys are in PKCS#8 format and can be output as PEM (default) or DER.

Examples:
  # List all supported key types
  go-fdo-tool keygen --list

  # Generate ECDSA P-384 key (recommended for FDO)
  go-fdo-tool keygen --type ecdsa-p384 --private-key owner_key.pem

  # Generate RSA 2048 key in DER format
  go-fdo-tool keygen --type rsa-2048 --format der --private-key key.der

  # Generate key and also save public key
  go-fdo-tool keygen --type ecdsa-p256 --private-key key.pem --public-key key_pub.pem

  # Generate key to stdout (useful for piping)
  go-fdo-tool keygen --type ecdsa-p384`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Check if --list flag is set
		listFlag, _ := cmd.Flags().GetBool("list")
		if listFlag {
			// Output supported key types in JSON format
			keyTypes := keygen.GetSupportedKeyTypesInfo()
			output := map[string]any{
				"supportedKeyTypes": keyTypes,
			}
			data, err := json.MarshalIndent(output, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal JSON: %w", err)
			}
			fmt.Println(string(data))
			return nil
		}

		keyTypeStr, _ := cmd.Flags().GetString("type")
		formatStr, _ := cmd.Flags().GetString("format")
		privateKeyPath, _ := cmd.Flags().GetString("private-key")
		publicKeyPath, _ := cmd.Flags().GetString("public-key")

		// Parse key type
		keyType, err := keygen.ParseKeyType(keyTypeStr)
		if err != nil {
			return err
		}

		// Parse format
		format, err := keygen.ParseFormat(formatStr)
		if err != nil {
			return err
		}

		// Generate the key
		fmt.Fprintf(os.Stderr, "Generating %s key...\n", keyTypeStr)
		key, err := keygen.GenerateKey(keyType)
		if err != nil {
			return fmt.Errorf("failed to generate key: %w", err)
		}

		// Get key info
		info := keygen.GetKeyInfo(key)
		fmt.Fprintf(os.Stderr, "Generated %s key (%s bits)\n", info["type"], info["bits"])
		if curve, ok := info["curve"]; ok {
			fmt.Fprintf(os.Stderr, "Curve: %s\n", curve)
		}

		// Save or output private key
		if privateKeyPath != "" {
			if err := keygen.SavePrivateKey(key, privateKeyPath, format); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Private key saved to: %s\n", privateKeyPath)
		} else {
			// Output to stdout
			data, err := keygen.EncodePrivateKey(key, format)
			if err != nil {
				return err
			}
			fmt.Print(string(data))
		}

		// Save public key if requested
		if publicKeyPath != "" {
			publicKey := key.Public()
			if err := keygen.SavePublicKey(publicKey, publicKeyPath, format); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "Public key saved to: %s\n", publicKeyPath)
		}

		return nil
	},
}

func init() {
	keygenCmd.Flags().StringP("type", "t", "ecdsa-p384", "Key type (ecdsa-p256, ecdsa-p384, rsa-2048, rsa-3072, rsa-4096)")
	keygenCmd.Flags().StringP("format", "f", "pem", "Output format (pem or der)")
	keygenCmd.Flags().String("private-key", "", "Output file for private key (stdout if not specified)")
	keygenCmd.Flags().String("public-key", "", "Optional output file for public key")
	keygenCmd.Flags().Bool("list", false, "List all supported key types in JSON format")
}
