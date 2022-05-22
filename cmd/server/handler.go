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
	}

	// TODO: return another template showing the signed in linking key.
	_ = linkingKey
}

func SafeURL(url string) template.URL {
	return template.URL(url)
}
