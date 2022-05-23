package main

import (
	"embed"
	"flag"
	"fmt"
	"html/template"
	"log"

	"github.com/gin-gonic/gin"
)

//go:embed templates/*
var f embed.FS

func main() {
	portPtr := flag.Int("port", 8080, "TCP port to run")
	hostnamePtr := flag.String("hostname", "", "Hostname of the server (e.g. http://192.168.1.10:8080)")
	flag.Parse()

	if *hostnamePtr == "" {
		log.Fatal("--hostname flag is required")
	}

	runServer(*hostnamePtr, *portPtr)
}

// runServer initiates an HTTP server containing the demo application of
// LNURL-auth authentication strategy. The `hostname` parameter is used to
// further generate LNURL and the `port` parameter is the server port on which
// you desire to run on.
func runServer(hostname string, port int) {
	// Setup handler functions.
	lnurlAuth := NewAuth(hostname)
	handler := NewHandler(lnurlAuth)

	// Setup HTML templates for the handlers to use.
	tmpl := template.Must(template.New("").
		Funcs(template.FuncMap{"safeURL": safeURL}).
		ParseFS(f, "templates/*.tmpl"))

	r := gin.Default()
	r.SetHTMLTemplate(tmpl)

	r.GET("/", lnurlAuth.Middleware, handler.Home)
	r.GET("/login", handler.Login)
	r.GET("/logout", lnurlAuth.Middleware, handler.Logout)

	r.Run(fmt.Sprintf(":%d", port))
}
