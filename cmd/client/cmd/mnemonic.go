package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
)

const mnemonicFileName = "mnemonic.txt"

func init() {
	rootCmd.AddCommand(mnemonicCmd)
}

// mnemonicCmd is a sub-command that performs random mnemonic generation.
var mnemonicCmd = &cobra.Command{
	Use:   "mnemonic",
	Short: "generates random mnemonic prior to authentication",
	Run: func(cmd *cobra.Command, args []string) {
		// Generates random entropy.
		entropy, err := bip39.NewEntropy(128)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bip39.NewEntropy: "+err.Error())
			return
		}

		// Converts entropy to mnemonic with checksum.
		mnemonic, err := bip39.NewMnemonic(entropy)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bip39.NewMnemonic: "+err.Error())
			return
		}

		// Saves mnemonic to file.
		file, err := os.Create(mnemonicFileName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "os.Create: "+err.Error())
			return
		}
		defer file.Close()

		if _, err := file.WriteString(mnemonic); err != nil {
			fmt.Fprintln(os.Stderr, "file.WriteString: "+err.Error())
			return
		}

		if err := file.Sync(); err != nil {
			fmt.Fprintln(os.Stderr, "file.Sync: "+err.Error())
			return
		}

		fmt.Printf("Mnemonic has been written to %s:\n", mnemonicFileName)
		fmt.Printf("  %s\n", mnemonic)
	},
}
