package parser

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// NormalizeTokenString trims whitespace and strips a leading "Bearer" prefix
// in a case-insensitive, whitespace-tolerant way.
func NormalizeTokenString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// Case-insensitive, tolerate extra spaces: only strip when followed by whitespace
	if len(s) >= len("Bearer") && strings.EqualFold(s[:len("Bearer")], "bearer") {
		rest := s[len("Bearer"):]
		if rest != "" {
			r, size := utf8.DecodeRuneInString(rest)
			if unicode.IsSpace(r) {
				return strings.TrimSpace(rest[size:])
			}
		}
	}
	return s
}
