package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

var (
	withHeader    = flag.Bool("header", false, "show header")
	withClaims    = flag.Bool("claims", true, "show the claims")
	withSignature = flag.Bool("sig", false, "shows the signature")
)

func main() {
	flag.Parse()
	flag.Usage = help

	if flag.NArg() == 0 {
		if err := parseToken(os.Stdin); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}

	for _, token := range flag.Args() {
		if token == "Bearer" || token == "bearer" {
			continue
		}
		if err := parseToken(strings.NewReader(token)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}
}

func parseToken(src io.Reader) error {
	b, err := ioutil.ReadAll(src)
	if err != nil {
		return nil
	}

	tokenString := string(b)

	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return err
	}

	if *withHeader {
		printJSON(token.Header)
	}
	if *withClaims {
		printJSON(token.Claims)
	}
	if *withSignature {
		printJSON(token.Signature)
	}

	return nil
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "   ")
	enc.Encode(v)
}

func help() {
	fmt.Println("jwtdebug <token>")
}
