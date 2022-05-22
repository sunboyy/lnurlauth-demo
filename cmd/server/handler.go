package main

import (
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	auth *Auth
}

func NewHandler(auth *Auth) *Handler {
	return &Handler{
		auth: auth,
	}
}

// Home is a Gin handler for the index page. It has two conditions to show the
// page. If the user is not signed in, it will show the sign in page with
// the newly generated challenge information. Otherwise, it will display the
// page with signed in linking key information.
func (h *Handler) Home(c *gin.Context) {
	// Get session id from the request context.
	sessionIDIntf, ok := c.Get(sessionIDContextKey)
	if !ok {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "unexpected a request context with no session id"},
		)
		return
	}

	sessionID, ok := sessionIDIntf.(string)
	if !ok {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{"error": "unexpected session id with invalid type"},
		)
		return
	}

	linkingKey, ok := h.auth.LinkingKey(sessionID)
	if !ok {
		authChallenge, err := h.auth.Challenge(sessionID)
		if err != nil {
			c.JSON(
				http.StatusInternalServerError,
				gin.H{"error": err.Error()},
			)
			return
		}

		c.HTML(http.StatusOK, "login.tmpl", authChallenge)
		return
	}

	c.HTML(http.StatusOK, "index.tmpl", gin.H{
		"LinkingKey": linkingKey,
	})
}

// Logout is a Gin handler for logging the user out. It logs the user out from
// the authentication service, removes session ID from the request cookie and
// then redirects the user to the index page.
func (h *Handler) Logout(c *gin.Context) {
	// Always redirect to home screen.
	defer c.Redirect(http.StatusTemporaryRedirect, "/")

	sessionIDIntf, ok := c.Get(sessionIDContextKey)
	if !ok {
		return
	}

	sessionID, ok := sessionIDIntf.(string)
	if !ok {
		return
	}

	// Remove session ID from the authentication service.
	h.auth.Logout(sessionID)

	// Unset session ID cookie.
	c.SetCookie(sessionKey, "", sessionAge, "/", c.Request.Host, false, true)
}

func SafeURL(url string) template.URL {
	return template.URL(url)
}
