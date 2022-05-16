package internal

import "time"

type LNURLAuthChallenge struct {
	LNURL     string    `json:"lnurl"`
	QRCodeURL string    `json:"qrcode"`
	ExpiresAt time.Time `json:"expiresAt"`
}
