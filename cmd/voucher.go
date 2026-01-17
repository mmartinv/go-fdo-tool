package cmd

import (
	"fmt"

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

func init() {
	voucherCmd.AddCommand(printCmd)
	voucherCmd.AddCommand(extendCmd)

	printCmd.Flags().Bool("json", false, "Output in JSON format")
	extendCmd.Flags().StringP("output", "o", "", "Output path for extended voucher (defaults to input file)")
}
