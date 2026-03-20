package parser

import (
	"regexp"
	"strings"
)

// jwtPattern matches a JWT token: three base64url-encoded parts separated by dots.
// The header and payload always start with "eyJ" (base64 of `{"`).
// Signature may be empty for unsecured JWTs (alg=none).
var jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`)

// NormalizeTokenString extracts a JWT token from the input string.
// When strict is true, it only trims whitespace and expects an exact token.
// When false (smart mode), it finds the first JWT-shaped string in the input,
// handling cases like "Bearer eyJ...", "cookie_name=eyJ...", etc.
func NormalizeTokenString(s string, strict bool) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}

	if strict {
		return s
	}

	if match := jwtPattern.FindString(s); match != "" {
		return match
	}

	return s
}
