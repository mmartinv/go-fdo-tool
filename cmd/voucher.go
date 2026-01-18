package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/mmartinv/go-fdo-tool/pkg/voucher"
	"github.com/spf13/cobra"
)

var voucherCmd = &cobra.Command{
	Use:   "voucher",
	Short: "Manage FDO ownership vouchers",
	Long:  `Commands for working with FDO ownership vouchers, including printing information and extending ownership.`,
}

var printCmd = &cobra.Command{
	Use:   "print <voucher-file>",
	Short: "Print ownership voucher information",
	Long:  `Display detailed information about an FDO ownership voucher from a file.`,
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		voucherPath := args[0]
		jsonOutput, _ := cmd.Flags().GetBool("json")

		ov, err := voucher.LoadFromFile(voucherPath)
		if err != nil {
			return fmt.Errorf("failed to load voucher: %w", err)
		}

		if jsonOutput {
			data, err := voucher.ToJSON(ov)
			if err != nil {
				return fmt.Errorf("failed to convert voucher to JSON: %w", err)
			}
			fmt.Println(string(data))
		} else {
			fmt.Print(voucher.ToText(ov))
		}

		return nil
	},
}

var extendCmd = &cobra.Command{
	Use:   "extend <voucher-file> <owner-private-key> <new-owner-public-key-or-cert>",
	Short: "Extend ownership voucher",
	Long: `Extend an ownership voucher by adding a new owner's public key or certificate.

The owner-private-key must be the private key of the current owner (the last entry in the voucher,
or the manufacturer key if the voucher has no entries). Supports both PEM and DER formats.

The new-owner-public-key-or-cert can be either:
  - A public key file (PEM format)
  - A certificate file (PEM format)
  - A certificate chain file (multiple PEM certificates)

IMPORTANT: The new owner's key type and size must match the manufacturer's key type.
  - If the manufacturer uses ECDSA P-384, all owners must use ECDSA P-384
  - If the manufacturer uses ECDSA P-256, all owners must use ECDSA P-256
  - If the manufacturer uses RSA 2048, all owners must use RSA 2048
  - If the manufacturer uses RSA 3072, all owners must use RSA 3072
Mixed key types are not supported in the ownership chain.

By default, the extended voucher is written to stdout. Use -o to save to a file.`,
	Args: cobra.ExactArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		voucherPath := args[0]
		ownerKeyPath := args[1]
		newOwnerPath := args[2]
		outputPath, _ := cmd.Flags().GetString("output")

		// Load the voucher
		ov, err := voucher.LoadFromFile(voucherPath)
		if err != nil {
			return fmt.Errorf("failed to load voucher: %w", err)
		}

		// Load the current owner's private key
		ownerKey, err := voucher.LoadPrivateKeyFromFile(ownerKeyPath)
		if err != nil {
			return fmt.Errorf("failed to load owner private key: %w", err)
		}

		// Load the new owner's public key or certificate
		newOwner, err := voucher.LoadPublicKeyOrCertFromFile(newOwnerPath)
		if err != nil {
			return fmt.Errorf("failed to load new owner public key or certificate: %w", err)
		}

		// Extend the voucher
		extended, err := voucher.Extend(ov, ownerKey, newOwner)
		if err != nil {
			return fmt.Errorf("failed to extend voucher: %w", err)
		}

		// Output the extended voucher
		if outputPath != "" {
			// Save to file
			if err := voucher.SaveToFile(extended, outputPath); err != nil {
				return fmt.Errorf("failed to save extended voucher: %w", err)
			}
			fmt.Printf("Extended voucher saved to: %s\n", outputPath)
		} else {
			// Write to stdout
			pemData, err := voucher.ToPEM(extended)
			if err != nil {
				return fmt.Errorf("failed to encode voucher: %w", err)
			}
			fmt.Print(string(pemData))
		}

		return nil
	},
}

var verifyCmd = &cobra.Command{
	Use:   "verify <voucher-file>",
	Short: "Verify ownership voucher",
	Long: `Verify the cryptographic integrity of an ownership voucher.

By default, performs basic verification that doesn't require secrets:
  - Validates ownership chain signatures (VerifyEntries)
  - Validates certificate chain hash (VerifyCertChainHash)
  - Validates device certificate chain (self-signed)
  - Validates manufacturer certificate chain (self-signed)

For full verification, provide device credential with --credential flag.
For CA root validation, provide trusted roots with --ca-certs flag.

Exit codes:
  0 - All verification checks passed
  1 - One or more verification checks failed
  2 - Usage/argument errors`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		voucherPath := args[0]

		// Get flags
		credentialPath, _ := cmd.Flags().GetString("credential")
		hmacSecretHex, _ := cmd.Flags().GetString("hmac-secret")
		hmacSecretFile, _ := cmd.Flags().GetString("hmac-secret-file")
		publicKeyHashStr, _ := cmd.Flags().GetString("public-key-hash")
		publicKeyHashFile, _ := cmd.Flags().GetString("public-key-hash-file")
		caCertsPath, _ := cmd.Flags().GetString("ca-certs")
		jsonOutput, _ := cmd.Flags().GetBool("json")

		// Load the voucher
		ov, err := voucher.LoadFromFile(voucherPath)
		if err != nil {
			return fmt.Errorf("failed to load voucher: %w", err)
		}

		// Build verification options
		opts := &voucher.VerifyOptions{}

		// Load HMAC secret (from credential, hex string, or file)
		if credentialPath != "" {
			cred, err := voucher.LoadDeviceCredentialFromFile(credentialPath)
			if err != nil {
				return fmt.Errorf("failed to load device credential: %w", err)
			}
			opts.HmacSecret = cred.HmacSecret
			opts.PublicKeyHash = &cred.PublicKeyHash
		}

		// HMAC secret from hex string (overrides credential)
		if hmacSecretHex != "" {
			secret, err := voucher.ParseHmacSecret(hmacSecretHex)
			if err != nil {
				return fmt.Errorf("failed to parse HMAC secret: %w", err)
			}
			opts.HmacSecret = secret
		}

		// HMAC secret from file (overrides credential and hex string)
		if hmacSecretFile != "" {
			secret, err := voucher.LoadHmacSecretFromFile(hmacSecretFile)
			if err != nil {
				return fmt.Errorf("failed to load HMAC secret from file: %w", err)
			}
			opts.HmacSecret = secret
		}

		// Public key hash from string (overrides credential)
		if publicKeyHashStr != "" {
			// Parse format: "ALGORITHM:HEXVALUE"
			var algorithm, hexValue string
			if _, err := fmt.Sscanf(publicKeyHashStr, "%[^:]:%s", &algorithm, &hexValue); err != nil {
				return fmt.Errorf("invalid public key hash format: expected 'ALGORITHM:HEXVALUE'")
			}
			hash, err := voucher.ParsePublicKeyHash(algorithm, hexValue)
			if err != nil {
				return fmt.Errorf("failed to parse public key hash: %w", err)
			}
			opts.PublicKeyHash = hash
		}

		// Public key hash from file (overrides credential and string)
		if publicKeyHashFile != "" {
			hash, err := voucher.LoadPublicKeyHashFromFile(publicKeyHashFile)
			if err != nil {
				return fmt.Errorf("failed to load public key hash from file: %w", err)
			}
			opts.PublicKeyHash = hash
		}

		// CA certificates
		if caCertsPath != "" {
			caCerts, err := voucher.LoadCACertsFromFile(caCertsPath)
			if err != nil {
				return fmt.Errorf("failed to load CA certificates: %w", err)
			}
			opts.TrustedRoots = caCerts
		}

		// Perform verification
		result := voucher.Verify(ov, opts)

		// Output results
		if jsonOutput {
			outputJSON(result)
		} else {
			outputText(result)
		}

		// Exit with appropriate code
		if !result.Passed {
			os.Exit(1)
		}

		return nil
	},
}

func outputText(result *voucher.VerifyResult) {
	// Print header
	if result.Passed {
		fmt.Println("VERIFICATION RESULT: PASSED")
	} else {
		fmt.Println("VERIFICATION RESULT: FAILED")
	}
	fmt.Println("========================================")
	fmt.Println()

	// Print check results
	passedCount := 0
	failedCount := 0
	for _, check := range result.Checks {
		if check.Passed {
			fmt.Printf("✓ %s: Valid\n", check.Name)
			passedCount++
		} else {
			fmt.Printf("✗ %s: Failed\n", check.Name)
			if check.Error != nil {
				fmt.Printf("  Error: %s\n", check.Error.Error())
			}
			failedCount++
		}
	}

	// Print summary
	fmt.Println()
	if result.Passed {
		fmt.Println("All checks passed.")
	} else {
		fmt.Printf("%d of %d checks failed.\n", failedCount, passedCount+failedCount)
	}
}

func outputJSON(result *voucher.VerifyResult) {
	type jsonCheck struct {
		Name   string  `json:"name"`
		Passed bool    `json:"passed"`
		Error  *string `json:"error,omitempty"`
	}

	type jsonOutput struct {
		Passed  bool        `json:"passed"`
		Checks  []jsonCheck `json:"checks"`
		Summary struct {
			Total  int `json:"total"`
			Passed int `json:"passed"`
			Failed int `json:"failed"`
		} `json:"summary"`
	}

	output := jsonOutput{
		Passed: result.Passed,
		Checks: make([]jsonCheck, 0, len(result.Checks)),
	}

	passedCount := 0
	for _, check := range result.Checks {
		jc := jsonCheck{
			Name:   check.Name,
			Passed: check.Passed,
		}
		if check.Error != nil {
			errStr := check.Error.Error()
			jc.Error = &errStr
		}
		output.Checks = append(output.Checks, jc)
		if check.Passed {
			passedCount++
		}
	}

	output.Summary.Total = len(result.Checks)
	output.Summary.Passed = passedCount
	output.Summary.Failed = output.Summary.Total - passedCount

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}

func init() {
	voucherCmd.AddCommand(printCmd)
	voucherCmd.AddCommand(extendCmd)
	voucherCmd.AddCommand(verifyCmd)

	printCmd.Flags().Bool("json", false, "Output in JSON format")
	extendCmd.Flags().StringP("output", "o", "", "Output path for extended voucher (defaults to input file)")

	verifyCmd.Flags().String("credential", "", "Device credential file for full verification")
	verifyCmd.Flags().String("hmac-secret", "", "HMAC secret as hex string")
	verifyCmd.Flags().String("hmac-secret-file", "", "File containing HMAC secret (hex or binary)")
	verifyCmd.Flags().String("public-key-hash", "", "Public key hash as 'ALGORITHM:HEXVALUE' (e.g., 'SHA256:abcd...')")
	verifyCmd.Flags().String("public-key-hash-file", "", "File containing public key hash")
	verifyCmd.Flags().String("ca-certs", "", "CA certificate bundle for trusted chain verification")
	verifyCmd.Flags().Bool("json", false, "Output results in JSON format")
}
