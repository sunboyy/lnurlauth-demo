package internal

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
	sessionKey        = "lnurl_sess"
	sessionAge        = 3600
	lnurlAuthHost     = "http://localhost:8080"
	lnurlAuthEndpoint = "/login"
)

type LNURLAuth struct {
	sessionCache   *cache.Cache
	challengeCache *cache.Cache
}

func NewLNURLAuth() *LNURLAuth {
	return &LNURLAuth{
		sessionCache:   cache.New(time.Second*sessionAge, time.Minute*10),
		challengeCache: cache.New(time.Second*sessionAge, time.Minute*10),
	}
}

// GetChallenge is a Gin handler to get LNURL auth challenge.
func (a *LNURLAuth) GetChallenge(c *gin.Context) {
	// Get session id from the cookie
	sessionID, err := c.Cookie(sessionKey)
	// If session id is not found, create and set a new session id.
	if err != nil {
		sessionID = a.random32BytesHex()
		if err := a.sessionCache.Add(sessionID, false, cache.DefaultExpiration); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.SetCookie(sessionKey, sessionID, sessionAge, "/", c.Request.Host, false, true)
	}

	// Create a random challenge and add to the challenge cache. Only the challenge in this cache is allowed to login.
	k1 := a.random32BytesHex()
	if err := a.challengeCache.Add(k1, sessionID, cache.DefaultExpiration); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Construct a login URL for the lightning wallet application to call. This also include previously generated challenge.
	actualURL := fmt.Sprintf("%s%s?tag=login&k1=%s", lnurlAuthHost, lnurlAuthEndpoint, k1)
	// Encode the login URL in bech32 format for lightning wallet application
	lnurl, err := lnurl.LNURLEncode(actualURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Append bech32-encoded URL with lightning protocol so that OS can redirect the link to an appropriate app.
	lnurl = pkg.LNURLProtocolPrefix + lnurl

	// Generate a QR code image for the encoded LNURL
	qrcodePNG, err := qrcode.Encode(lnurl, qrcode.Medium, 256)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, LNURLAuthChallenge{
		LNURL:     lnurl,
		QRCodeURL: "data:image/png;base64," + base64.StdEncoding.EncodeToString(qrcodePNG),
		ExpiresAt: time.Now().Add(time.Second * sessionAge),
	})
}

// Login is a Gin handler to handle request from Bitcoin Lightning wallet application.
func (a *LNURLAuth) Login(c *gin.Context) {
	if c.Query("tag") != "login" {
		c.JSON(http.StatusBadRequest, createErrorResponse("query parameter `tag` is not 'login'"))
		return
	}

	k1 := c.Query("k1")
	linkingKey := c.Query("key")
	signature := c.Query("sig")

	// check k1 in cache

	ok, err := lnurl.VerifySignature(k1, signature, linkingKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, createErrorResponse(err.Error()))
		return
	}
	if !ok {
		c.JSON(http.StatusBadRequest, createErrorResponse("invalid signature"))
	}

	c.JSON(http.StatusOK, pkg.LNURLAuthResponse{Status: pkg.LNURLAuthResponseStatusOK})
}

func (s *LNURLAuth) random32BytesHex() string {
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
