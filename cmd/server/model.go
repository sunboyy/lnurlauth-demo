package main

// AuthChallenge contains the challenge data used for autentication.
type AuthChallenge struct {
	// LNURL is an authentication URL that is compatible with Bitcoin Lightning
	// Wallet applications. It is a bech32-encoded URL with "lightning:"
	// protocol scheme.
	LNURL string `json:"lnurl"`

	// QRCodeURL is a URL of the QR code image which represents the previously
	// described LNURL. It creates more convinence to the user as the user can
	// scan the QR code in this image instead of copying the LNURL.
	QRCodeURL string `json:"qrcodeUrl"`
}
