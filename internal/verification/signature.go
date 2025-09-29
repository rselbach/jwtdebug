package verification

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rselbach/jwtdebug/internal/cli"
)

// VerifyTokenSignature verifies the token signature using the provided key file
func VerifyTokenSignature(tokenString string) error {
	if cli.KeyFile == "" {
		return errors.New("key file not provided (-key flag required)")
	}

	stat, err := os.Stat(cli.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to stat key file: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return errors.New("key file must be a regular file")
	}

	// read key file
	keyData, err := os.ReadFile(cli.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// parse the token with verification
	var parseOpts []jwt.ParserOption
	// Restrict accepted algorithms to known-safe set
	parseOpts = append(parseOpts, jwt.WithValidMethods([]string{
		"HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512",
		"EdDSA",
	}))
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
		case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
			// RSA and RSA-PSS algorithms use an RSA public key
			return jwt.ParseRSAPublicKeyFromPEM(keyData)
		case "ES256", "ES384", "ES512":
			// ECDSA algorithms use an EC public key
			return jwt.ParseECPublicKeyFromPEM(keyData)
		case "EdDSA":
			// Ed25519 public key
			return jwt.ParseEdPublicKeyFromPEM(keyData)
		default:
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
	}, parseOpts...)

	return err
}
