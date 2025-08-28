package parser

import "strings"

// NormalizeTokenString trims whitespace and strips a leading "Bearer" prefix
// in a case-insensitive, whitespace-tolerant way.
func NormalizeTokenString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	// Case-insensitive, tolerate extra spaces: ^Bearer\s+
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "bearer") {
		rest := strings.TrimSpace(s[len("Bearer"):])
		return rest
	}
	return s
}
