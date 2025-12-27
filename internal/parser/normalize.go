package parser

import (
	"regexp"
	"strings"

	"github.com/rselbach/jwtdebug/internal/cli"
)

// jwtPattern matches a JWT token: three base64url-encoded parts separated by dots.
// The header and payload always start with "eyJ" (base64 of `{"`).
var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+`)

// NormalizeTokenString extracts a JWT token from the input string.
// By default (smart mode), it finds the first JWT-shaped string in the input,
// handling cases like "Bearer eyJ...", "cookie_name=eyJ...", etc.
// With --strict, it only trims whitespace and expects an exact token.
func NormalizeTokenString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	// Strict mode: return as-is (just trimmed)
	if cli.Strict {
		return s
	}

	// Smart mode: extract JWT from anywhere in the input
	if match := jwtPattern.FindString(s); match != "" {
		return match
	}

	// No JWT found, return original (will fail validation with helpful error)
	return s
}
