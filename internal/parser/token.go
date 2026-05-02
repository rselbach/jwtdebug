package parser

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ParsedToken holds the result of parsing a JWT token string.
type ParsedToken struct {
	Token  *jwt.Token
	Parts  []string
	Claims jwt.MapClaims
}

// ParseToken parses a JWT token string and returns the parsed data.
// It validates the token format (must have 3 dot-separated parts) and
// decodes the header and claims without verifying the signature.
func ParseToken(tokenString string) (*ParsedToken, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		snippet := tokenSnippet(tokenString)
		return nil, fmt.Errorf("invalid token format: expected 3 parts separated by '.', got %d (token: %s)", len(parts), snippet)
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		snippet := tokenSnippet(tokenString)
		return nil, fmt.Errorf("failed to parse token (%s): %w", snippet, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("could not extract claims from token")
	}

	return &ParsedToken{Token: token, Parts: parts, Claims: claims}, nil
}

func tokenSnippet(token string) string {
	if len(token) <= 20 {
		return token
	}
	return token[:17] + "..."
}
