package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// config holds the application configuration and flags
type config struct {
	showHeader    bool
	showClaims    bool
	showSignature bool
	tokens        []string
}

// tokenParser handles JWT token parsing operations
type tokenParser struct {
	cfg    config
	parser *jwt.Parser
}

// newTokenParser creates a new tokenParser instance
func newTokenParser(cfg config) *tokenParser {
	return &tokenParser{
		cfg:    cfg,
		parser: new(jwt.Parser),
	}
}

func (tp *tokenParser) parseFromReader(src io.Reader) error {
	content, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("reading token: %w", err)
	}

	return tp.parse(string(content))
}

func (tp *tokenParser) parse(tokenString string) error {
	token, _, err := tp.parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("parsing token: %w", err)
	}

	return tp.printTokenParts(token)
}

func (tp *tokenParser) printTokenParts(token *jwt.Token) error {
	if tp.cfg.showHeader {
		if err := printJSON(token.Header); err != nil {
			return fmt.Errorf("printing header: %w", err)
		}
	}
	if tp.cfg.showClaims {
		if err := printJSON(token.Claims); err != nil {
			return fmt.Errorf("printing claims: %w", err)
		}
	}
	if tp.cfg.showSignature {
		if err := printJSON(token.Signature); err != nil {
			return fmt.Errorf("printing signature: %w", err)
		}
	}
	return nil
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "   ")
	return enc.Encode(v)
}

func parseFlags() config {
	var cfg config
	flag.BoolVar(&cfg.showHeader, "header", false, "show header")
	flag.BoolVar(&cfg.showClaims, "claims", true, "show the claims")
	flag.BoolVar(&cfg.showSignature, "sig", false, "shows the signature")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <token>\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.Parse()

	cfg.tokens = flag.Args()
	return cfg
}

func run(cfg config) error {
	parser := newTokenParser(cfg)

	if len(cfg.tokens) == 0 {
		return parser.parseFromReader(os.Stdin)
	}

	for _, token := range cfg.tokens {
		if isBearer(token) {
			continue
		}
		if err := parser.parse(token); err != nil {
			return err
		}
	}
	return nil
}

func isBearer(token string) bool {
	return strings.EqualFold(token, "bearer")
}
