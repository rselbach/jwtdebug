package verification

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
	
	"jwtdebug/internal/cli"
)

// VerifyTokenSignature verifies the token signature using the provided key file
func VerifyTokenSignature(tokenString string) error {
	if cli.KeyFile == "" {
		return errors.New("key file not provided (-key flag required)")
	}

	// read key file
	keyData, err := os.ReadFile(cli.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// parse the token with verification
	var parseOpts []jwt.ParserOption
	if cli.IgnoreExpiration {
		parseOpts = append(parseOpts, jwt.WithoutClaimsValidation())
	}

	// parse using the provided key
	_, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// check signature algorithm
		switch token.Method.Alg() {
		case "HS256", "HS384", "HS512":
			// HMAC algorithms use the key directly
			return keyData, nil
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512":
			// RSA and ECDSA algorithms use a public key
			return jwt.ParseRSAPublicKeyFromPEM(keyData)
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	}, parseOpts...)

	return err
}
