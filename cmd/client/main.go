package main

import (
	"fmt"
	"os"

	"github.com/sunboyy/lnurlauth/cmd/client/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
}
