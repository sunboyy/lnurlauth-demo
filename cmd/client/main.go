package main

import (
	"bufio"
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
	"github.com/sunboyy/lnurlauth/pkg"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func main() {
	// Read LNURL from STDIN.
	lnurlBech32, err := readLNURL()
	if err != nil {
		fmt.Fprintf(os.Stdout, "❌ Error: cannot read input: %s\n", err.Error())
		return
	}

	// Extract auth URL from LNURL.
	authURL, err := extractLNURL(lnurlBech32)
	if err != nil {
		fmt.Fprintf(os.Stdout, "❌ Error: cannot extract URL: %s\n", err.Error())
		return
	}

	k1Hex := authURL.Query().Get("k1")
	k1Bytes, err := hex.DecodeString(k1Hex)
	if err != nil {
		fmt.Fprintf(os.Stdout, "❌ Error: cannot decode challenge: %s\n", err.Error())
		return
	}

	fmt.Println("LNURL information:")
	fmt.Printf("  Auth URL = %s\n", authURL.String())
	fmt.Printf("  Hostname = %s\n", authURL.Hostname())
	fmt.Printf("  Challenge = %s\n", k1Hex)

	// Read mnemonic and passphrase from STDIN and convert to seed.
	seed, err := getSeedFromMnemonic()
	if err != nil {
		fmt.Fprintf(os.Stdout, "❌ Error: cannot get seed: %s\n", err.Error())
		return
	}

	// Derive key pair from seed and domain to log in
	privateKey, publicKey := getAuthLinkingKey(seed, authURL.Hostname())

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

	// Request authentication to the server.
	// if err := requestAuth(authURL); err != nil {
	// 	fmt.Fprintf(os.Stdout, "❌ Error: auth request failed: %s\n", err.Error())
	// 	return
	// }

	// fmt.Println("✅ Authentication success")
}

func readLNURL() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter LNURL > ")
	lnurlBech32, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(lnurlBech32, pkg.LNURLProtocolPrefix) {
		lnurlBech32 = lnurlBech32[len(pkg.LNURLProtocolPrefix):]
	}
	return strings.TrimSpace(lnurlBech32), nil
}

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

	// URL encoded in the LNURL must have query parameter tag='login' so that the wallet app knows what to do.
	tag := authURL.Query().Get("tag")
	if tag != "login" {
		return nil, errors.New("this lnurl is not used for authentication")
	}

	return authURL, nil
}

func getSeedFromMnemonic() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter Mnemonic > ")
	mnemonic, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	mnemonic = strings.TrimSpace(mnemonic)

	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, errors.New("mnemonic is invalid")
	}

	fmt.Print("Enter Passphrase (if any) > ")
	passphrase, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}
	passphrase = strings.TrimSpace(passphrase)

	return bip39.NewSeed(mnemonic, passphrase), nil
}

func getAuthLinkingKey(seed []byte, domain string) (*btcec.PrivateKey, *btcec.PublicKey) {
	// Hashing key for HMAC-SHA256 is derived from BIP-32 HD wallet: m/138'/0
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

	// Linking private key (private key for signing the challenge) is derived from BIP-32 HD wallet: m/138'/<long1>/<long2>/<long3>/<long4>
	bip32PrivateKey, _ := authMasterKey.NewChildKey(childIndex1)
	bip32PrivateKey, _ = bip32PrivateKey.NewChildKey(childIndex2)
	bip32PrivateKey, _ = bip32PrivateKey.NewChildKey(childIndex3)
	bip32PrivateKey, _ = bip32PrivateKey.NewChildKey(childIndex4)

	return btcec.PrivKeyFromBytes(bip32PrivateKey.Key)
}

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
