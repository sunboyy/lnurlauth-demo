package main

import (
	"github.com/gin-gonic/gin"
	"github.com/sunboyy/lnurlauth/cmd/server/internal"
)

func main() {
	lnurlAuth := internal.NewLNURLAuth()
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		// return web
	})

	r.GET("/challenge", lnurlAuth.GetChallenge)
	r.GET("/login", lnurlAuth.Login)

	r.Run()
}
