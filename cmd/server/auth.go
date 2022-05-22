package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
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

// Auth is a set of Gin middleware and handlers for the LNURL-auth strategy.
type Auth struct {
	hostname string

	// sessionCache is a storage of mappings between session id and linking key
	// (user's public key).
	sessionCache *cache.Cache

	// challengeCache is a storage of the randomized k1 challenge. Only the
	// k1 stored in this cache can be used to login.
	challengeCache *cache.Cache
}

// NewAuth is a constructor for `Auth`.
func NewAuth(hostname string) *Auth {
	return &Auth{
		hostname:       hostname,
		sessionCache:   cache.New(time.Second*sessionAge, time.Minute*10),
		challengeCache: cache.New(time.Second*sessionAge, time.Minute*10),
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
	// Create a random k1 challenge and add a mapping to session id to the
	// challenge cache.
	k1 := random32BytesHex()
	if err := a.challengeCache.Add(
		k1,
		sessionID,
		cache.DefaultExpiration,
	); err != nil {
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
		ExpiresAt: time.Now().Add(time.Second * sessionAge),
	}, nil
}

// Login is a Gin handler to handle the request with signed k1 challenge from
// Lightning wallet application. The following query params must be set:
//   - tag: fixed value "login"
//   - k1: the challenge from `Challenge` handler
//   - key: the identity of the user as public key (linking key)
//   - sig: the signature that verifies the identity of the user
//
// It finds the session ID related to the k1 challenge in the challenge cache
// and verifies the given signature. If the session ID is found and the
// signature is valid, the linking key will be set to the session cache.
func (a *Auth) Login(c *gin.Context) {
	// From the RFC (https://github.com/fiatjaf/lnurl-rfc/blob/luds/04.md), the
	// request must have the query `tag` to `login`.
	if c.Query("tag") != "login" {
		c.JSON(
			http.StatusBadRequest,
			createErrorResponse("query parameter `tag` is not 'login'"),
		)
		return
	}

	k1 := c.Query("k1")
	linkingKey := c.Query("key")
	signature := c.Query("sig")

	// Find the session ID in the challenge cache.
	sessionIDInf, ok := a.challengeCache.Get(k1)
	if !ok {
		c.JSON(
			http.StatusBadRequest,
			createErrorResponse("no session id found for this k1 challenge"),
		)
	}

	sessionID, ok := sessionIDInf.(string)
	if !ok {
		c.JSON(
			http.StatusInternalServerError,
			createErrorResponse("unexpected session id with invalid type"),
		)
	}

	// Verify the signature with the k1 challenge.
	ok, err := lnurl.VerifySignature(k1, signature, linkingKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, createErrorResponse(err.Error()))
		return
	}
	if !ok {
		c.JSON(http.StatusBadRequest, createErrorResponse("invalid signature"))
		return
	}

	// If the signature is correct, add a mapping from session id to linking key
	// to the session cache.
	a.sessionCache.Set(sessionID, linkingKey, cache.DefaultExpiration)

	c.JSON(http.StatusOK, pkg.LNURLAuthResponse{
		Status: pkg.LNURLAuthResponseStatusOK,
	})
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

func random32BytesHex() string {
	data := make([]byte, 32)
	_, _ = rand.Read(data)
	return hex.EncodeToString(data)
}

func createErrorResponse(reason string) pkg.LNURLAuthResponse {
	return pkg.LNURLAuthResponse{
		Status: pkg.LNURLAuthResponseStatusError,
		Reason: reason,
	}
}
