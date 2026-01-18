package cmd

import (
	"fmt"

	"github.com/mmartinv/go-fdo-tool/pkg/credential"
	"github.com/spf13/cobra"
)

var credentialCmd = &cobra.Command{
	Use:   "credential",
	Short: "Manage FDO device credentials",
	Long:  `Commands for working with FDO device credentials, including printing credential information.`,
}

var credPrintCmd = &cobra.Command{
	Use:   "print <credential-file>",
	Short: "Print device credential information",
	Long: `Display detailed information about an FDO device credential from a CBOR file.

By default, sensitive information (HMAC secret, private key) is hidden.
Use --show-secrets to display the full HMAC secret and private key in PEM format.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		credPath := args[0]
		jsonOutput, _ := cmd.Flags().GetBool("json")
		showSecrets, _ := cmd.Flags().GetBool("show-secrets")

		cred, err := credential.LoadFromFile(credPath)
		if err != nil {
			return fmt.Errorf("failed to load credential: %w", err)
		}

		if jsonOutput {
			data, err := credential.ToJSON(cred, showSecrets)
			if err != nil {
				return fmt.Errorf("failed to convert credential to JSON: %w", err)
			}
			fmt.Println(string(data))
		} else {
			fmt.Print(credential.ToText(cred, showSecrets))
		}

		return nil
	},
}

func init() {
	credentialCmd.AddCommand(credPrintCmd)

	credPrintCmd.Flags().Bool("json", false, "Output in JSON format")
	credPrintCmd.Flags().Bool("show-secrets", false, "Show sensitive information (HMAC secret, private key)")
}
