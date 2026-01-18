package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "go-fdo-tool",
	Short: "A CLI tool for managing FDO ownership vouchers and device credentials",
	Long:  `A command line tool for working with FIDO Device Onboard (FDO) ownership vouchers and device credentials.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(voucherCmd)
	rootCmd.AddCommand(credentialCmd)
	rootCmd.AddCommand(keygenCmd)
}
