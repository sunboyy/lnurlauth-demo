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

func runServer(hostname string, port int) {
	lnurlAuth := NewAuth(hostname)
	handler := NewHandler(lnurlAuth)

	r := gin.Default()
	tmpl := template.Must(template.New("").
		Funcs(template.FuncMap{"safeURL": SafeURL}).
		ParseFS(f, "templates/*.tmpl"))
	r.SetHTMLTemplate(tmpl)

	r.GET("/", lnurlAuth.Middleware, handler.Home)
	r.GET("/login", lnurlAuth.Login)
	r.GET("/logout", lnurlAuth.Middleware, handler.Logout)

	r.Run(fmt.Sprintf(":%d", port))
}
