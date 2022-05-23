package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/fiatjaf/go-lnurl"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/skip2/go-qrcode"
	"github.com/sunboyy/lnurlauth/pkg"
)

const (
	sessionKey           = "lnurl_sess"
	sessionAge           = 3600
	lnurlAuthEndpoint    = "/login"
	sessionIDContextKey  = "session_id"
	linkingKeyContextKey = "linking_key"
)

// Auth is an authentication service for the server. It utilizes digital
// signature algorithm to authenticate the user to the system. To authenticate
// a user, the system generates a random data for the user to sign. The user
// provides the public key identifying himself and a signature according to the
// random data that the server generates. Valid signatures indicate that the
// user is authentic and is allowed to use the system. Auth utilizes LNURL-auth
// standard (https://github.com/fiatjaf/lnurl-rfc/blob/luds/04.md) so that it
// is compatible with Bitcoin Lightning Wallet application.
type Auth struct {
	// hostname is the host name of the server that the client will call. It is
	// used for generating LNURL for the Bitcoin Lightning wallet application.
	hostname string

	// sessionCache is a storage of mappings between session id and linking key
	// (user's public key).
	sessionCache *cache.Cache

	// challengeCache is a storage of the randomized k1 challenge. Only the
	// k1 stored in this cache can be used to login.
	challengeCache *cache.Cache

	// reverseChallengeCache is a reverse mapping of challengeCache. Instead of
	// storing mappings from k1 challenge to session ID, this variable stores
	// mappings from session ID to k1 challenge.
	reverseChallengeCache *cache.Cache
}

// NewAuth is a constructor of Auth.
func NewAuth(hostname string) *Auth {
	return &Auth{
		hostname: hostname,
		sessionCache: cache.New(
			time.Second*sessionAge,
			time.Minute*10,
		),
		challengeCache: cache.New(
			time.Second*sessionAge,
			time.Minute*10,
		),
		reverseChallengeCache: cache.New(
			time.Second*sessionAge,
			time.Minute*10,
		),
	}
}

// Middleware is an authentication middleware based on LNURL-auth strategy. It
// tries to retrieve session ID cookie from the request, finds the linking key
// (user's public key) related to the session ID and sets the linking key to
// the request context with key `linking_key`. If session ID cookie does not
// exist in the request, it will generate a new session ID for the user.
func (a *Auth) Middleware(c *gin.Context) {
	// Always continue to the next middleware.
	defer c.Next()

	// Get session ID from the cookie.
	sessionID, err := c.Cookie(sessionKey)

	// If the request doesn't include session ID cookie, create and set a new
	// session ID.
	if err != nil {
		sessionID = random32BytesHex()
		c.Set(sessionIDContextKey, sessionID)
		c.SetCookie(
			sessionKey,
			sessionID,
			sessionAge,
			"/",
			c.Request.Host,
			false,
			true,
		)
		return
	}

	c.Set(sessionIDContextKey, sessionIDContextKey)

	// Try to retrieve linking key.
	linkingKey, ok := a.LinkingKey(sessionID)
	if ok {
		// If the user is signed in, set the linking key to the request context.
		c.Set(linkingKeyContextKey, linkingKey)
	}
}

// Challenge returns LNURL for the Lightning wallet application. It generates
// a k1 challenge (a random data for the wallet application to sign), creates a
// mapping with the session ID by setting into the challenge cache and then
// returns the LNURL that embeds the k1 challenge. A QR code image for the LNURL
// is also provided for convenience.
func (a *Auth) Challenge(sessionID string) (AuthChallenge, error) {
	// Finds or creates k1 challenge.
	k1, err := a.k1BySessionID(sessionID)
	if err != nil {
		return AuthChallenge{}, err
	}

	// Construct a login URL for the Lightning wallet application to call. This
	// includes previously generated k1 challenge.
	actualURL := fmt.Sprintf(
		"%s%s?tag=login&k1=%s",
		a.hostname,
		lnurlAuthEndpoint,
		k1,
	)

	// Encode the login URL in bech32 format for the Lightning wallet
	// application.
	lnurl, err := lnurl.LNURLEncode(actualURL)
	if err != nil {
		return AuthChallenge{}, err
	}

	// Append bech32-encoded URL with lightning protocol so that the operating
	// system can redirect the link to an appropriate app.
	lnurl = pkg.LNURLProtocolPrefix + lnurl

	// Generate a QR code image for the encoded LNURL
	qrcodePNG, err := qrcode.Encode(lnurl, qrcode.Medium, 256)
	if err != nil {
		return AuthChallenge{}, err
	}

	return AuthChallenge{
		LNURL: lnurl,
		QRCodeURL: "data:image/png;base64," +
			base64.StdEncoding.EncodeToString(qrcodePNG),
	}, nil
}

// k1BySessionID finds previously generated k1 challenge if any. Otherwise, it
// generates a new k1 challenge by randomization and stores to the challenge
// caches for further authentication.
func (a *Auth) k1BySessionID(sessionID string) (string, error) {
	// Finds previously generated k1 challenge in the cache.
	k1Intf, ok := a.reverseChallengeCache.Get(sessionID)
	if ok {
		k1, ok := k1Intf.(string)
		if ok {
			return k1, nil
		}
	}

	// Create a random k1 challenge.
	k1 := random32BytesHex()

	// Store a mapping between k1 challenge and session ID to the caches.
	if err := a.challengeCache.Add(
		k1,
		sessionID,
		cache.DefaultExpiration,
	); err != nil {
		return "", err
	}
	if err := a.reverseChallengeCache.Add(
		sessionID,
		k1,
		cache.DefaultExpiration,
	); err != nil {
		return "", err
	}

	return k1, nil
}

// Login logs the user in to the system using digital signature algorithm. It
// finds the session ID related to the k1 challenge in the challenge cache and
// verifies the given signature. If the session ID is found and the signature is
// valid, the linking key will be set to the session cache.
func (a *Auth) Login(k1 string, linkingKey string, signature string) error {
	// Find the session ID in the challenge cache.
	sessionIDInf, ok := a.challengeCache.Get(k1)
	if !ok {
		return errors.New("no session id found for this k1 challenge")
	}

	sessionID, ok := sessionIDInf.(string)
	if !ok {
		return errors.New("unexpected session id with invalid type")
	}

	// Verify the signature with the k1 challenge.
	ok, err := lnurl.VerifySignature(k1, signature, linkingKey)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("invalid signature")
	}

	// If the signature is correct, add a mapping from session id to linking key
	// to the session cache.
	a.sessionCache.Set(sessionID, linkingKey, cache.DefaultExpiration)

	// Delete from challenge caches.
	a.challengeCache.Delete(k1)
	a.reverseChallengeCache.Delete(sessionID)

	return nil
}

// Logout logs the user out of the system by removing the given session ID from
// the session cache.
func (a *Auth) Logout(sessionID string) {
	a.sessionCache.Delete(sessionID)
}

// LinkingKey returns linking key matched with the session ID by reading the
// session cache. If the linking key does not exist, it will return false in
// the second return value.
func (a *Auth) LinkingKey(sessionID string) (string, bool) {
	linkingKeyIntf, ok := a.sessionCache.Get(sessionID)
	if !ok {
		return "", false
	}

	linkingKey, ok := linkingKeyIntf.(string)
	if !ok {
		return "", false
	}

	return linkingKey, true
}

// random32BytesHex generates a random 32-byte data in a hexadecimal string
// format.
func random32BytesHex() string {
	data := make([]byte, 32)
	_, _ = rand.Read(data)
	return hex.EncodeToString(data)
}
