package main

import (
	"os"

	"github.com/rselbach/jwtdebug/internal/jwtdebug"
)

func main() {
	os.Exit(jwtdebug.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
