package main

import "time"

type AuthChallenge struct {
	LNURL     string    `json:"lnurl"`
	QRCodeURL string    `json:"qrcode"`
	ExpiresAt time.Time `json:"expiresAt"`
}
