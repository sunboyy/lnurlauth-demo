package cmd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/fiatjaf/go-lnurl"
	"github.com/spf13/cobra"
	"github.com/sunboyy/lnurlauth/pkg"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

var dryRunPtr *bool

func init() {
	dryRunPtr = authCmd.Flags().Bool(
		"dry-run",
		false,
		"Generate signed callback URL without requesting the URL",
	)
	rootCmd.AddCommand(authCmd)
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "performs lnurl authentication",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// Read mnemonic from mnemonic.txt file and convert to seed.
		seed, err := seedFromMnemonicFile()
		if err != nil {
			fmt.Fprintf(os.Stderr, "mnemonic: %s\n", err.Error())
			return
		}

		lnurlBech32 := strings.TrimPrefix(args[0], pkg.LNURLProtocolPrefix)

		// Extract auth URL from LNURL.
		authURL, err := extractLNURL(lnurlBech32)
		if err != nil {
			fmt.Fprintf(os.Stderr, "extractLNURL: %s\n", err.Error())
			return
		}

		// URL encoded in the LNURL must have query parameter tag='login' so
		// that the wallet app knows that this is an auth URL.
		tag := authURL.Query().Get("tag")
		if tag != "login" {
			fmt.Fprintf(os.Stderr, "lnurl: url is not used for authentication")
			return
		}

		k1Hex := authURL.Query().Get("k1")
		k1Bytes, err := hex.DecodeString(k1Hex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "decode k1: %s\n", err.Error())
			return
		}

		fmt.Println("LNURL information:")
		fmt.Printf("  Auth URL = %s\n", authURL.String())
		fmt.Printf("  Hostname = %s\n", authURL.Hostname())
		fmt.Printf("  Challenge = %s\n", k1Hex)

		// Derive key pair from seed and domain to log in
		privateKey, publicKey := deriveLinkingKey(seed, authURL.Hostname())

		linkingKey := publicKey.SerializeCompressed()
		signature, _ := privateKey.ToECDSA().Sign(rand.Reader, k1Bytes, nil)
		fmt.Println("Identity information:")
		fmt.Printf("  Linking key = %s\n", hex.EncodeToString(linkingKey))
		fmt.Printf("  Signature = %s\n", hex.EncodeToString(signature))

		query := authURL.Query()
		query.Add("sig", hex.EncodeToString(signature))
		query.Add("key", hex.EncodeToString(linkingKey))
		authURL.RawQuery = query.Encode()
		fmt.Printf("  Authed URL = %s\n", authURL.String())

		if !*dryRunPtr {
			// Request authentication to the server.
			if err := requestAuth(authURL); err != nil {
				fmt.Fprintf(os.Stderr, "requestAuth: %s\n", err.Error())
				return
			}

			fmt.Println("✅ Authentication success")
		}
	},
}

// extractLNURL decodes an LNURL to the plain URL of type *url.URL.
func extractLNURL(lnurlBech32 string) (*url.URL, error) {
	// Decode bech32-encoded LNURL to a regular URL.
	authURLString, err := lnurl.LNURLDecode(lnurlBech32)
	if err != nil {
		return nil, err
	}

	authURL, err := url.Parse(authURLString)
	if err != nil {
		return nil, err
	}

	return authURL, nil
}

// seedFromMnemonicFile creates a seed from mnemonic stored in mnemonic.txt
// file. Passphrase is ignored for simplicity.
func seedFromMnemonicFile() ([]byte, error) {
	dat, err := os.ReadFile(mnemonicFileName)
	if err != nil {
		return nil, err
	}

	mnemonic := strings.TrimSpace(string(dat))
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}

	return bip39.NewSeed(mnemonic, ""), nil
}

// deriveLinkingKey derives public-private key pair for the specific domain from
// the seed. Derivation path for the specific domain is:
//
// m/138'/<long1>/<long2>/<long3>/<long4>
//
// Four long values are calculated from HMAC-SHA256 of a domain with hashing key
// derived from the seed with path m/138'/0.
func deriveLinkingKey(seed []byte, domain string) (*btcec.PrivateKey,
	*btcec.PublicKey) {

	// Hashing key for HMAC-SHA256 is derived from BIP-32 HD wallet with
	// path m/138'/0
	masterKey, _ := bip32.NewMasterKey(seed)
	authMasterKey, _ := masterKey.NewChildKey(0x80000000 + 138)
	hashingKey, _ := authMasterKey.NewChildKey(0)

	h := hmac.New(sha256.New, hashingKey.Key)
	h.Write([]byte(domain))
	digest := h.Sum(nil)

	childIndex1 := binary.BigEndian.Uint32(digest[:4])
	childIndex2 := binary.BigEndian.Uint32(digest[4:8])
	childIndex3 := binary.BigEndian.Uint32(digest[8:12])
	childIndex4 := binary.BigEndian.Uint32(digest[12:16])

	// Linking private key (private key for signing the challenge) is
	// derived from BIP-32 HD wallet: m/138'/<long1>/<long2>/<long3>/<long4>
	bip32PrivateKey, _ := authMasterKey.NewChildKey(childIndex1)
	bip32PrivateKey, _ = bip32PrivateKey.NewChildKey(childIndex2)
	bip32PrivateKey, _ = bip32PrivateKey.NewChildKey(childIndex3)
	bip32PrivateKey, _ = bip32PrivateKey.NewChildKey(childIndex4)

	return btcec.PrivKeyFromBytes(bip32PrivateKey.Key)
}

// requestAuth requests an authentication to the target service. It directly
// sends GET request to the signed auth URL and formats the response as
// described is the LUD-04 spec.
func requestAuth(u *url.URL) error {
	res, err := http.Get(u.String())
	if err != nil {
		return err
	}
	defer res.Body.Close()

	var data pkg.LNURLAuthResponse
	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		return err
	}

	if data.Status != pkg.LNURLAuthResponseStatusOK {
		return errors.New(data.Reason)
	}

	return nil
}
