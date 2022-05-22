package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	portPtr := flag.Int("port", 8080, "TCP port to run")
	hostnamePtr := flag.String("hostname", "", "Hostname of the server (e.g. http://192.168.1.10:8080)")
	flag.Parse()

	if *hostnamePtr == "" {
		log.Fatal("--hostname flag is required")
	}

	runServer(*hostnamePtr, *portPtr)
}

func runServer(hostname string, port int) {
	lnurlAuth := NewAuth(hostname)

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		// TODO: return web
	})

	r.GET("/challenge", lnurlAuth.Middleware, lnurlAuth.Challenge)
	r.GET("/login", lnurlAuth.Login)

	r.Run(fmt.Sprintf(":%d", port))
}
