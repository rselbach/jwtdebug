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
	parseOpts := []jwt.ParserOption{jwt.WithValidMethods([]string{
		"HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512",
		"EdDSA",
	})}

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

	if err != nil && cli.IgnoreExpiration && onlyExpirationErrors(err) {
		return nil
	}

	return err
}

// onlyExpirationErrors reports whether the provided error (and any wrapped errors)
// consists exclusively of expiration-related validation failures.
func onlyExpirationErrors(err error) bool {
	if err == nil {
		return false
	}

	hasExpiration := false

	var walk func(error) bool
	walk = func(e error) bool {
		if e == nil {
			return true
		}

		if errors.Is(e, jwt.ErrTokenExpired) {
			hasExpiration = true
		} else if errors.Is(e, jwt.ErrTokenInvalidClaims) {
			// allowed wrapper, continue inspection
		} else {
			switch unw := e.(type) {
			case interface{ Unwrap() []error }:
				for _, inner := range unw.Unwrap() {
					if !walk(inner) {
						return false
					}
				}
				return true
			case interface{ Unwrap() error }:
				if inner := unw.Unwrap(); inner != nil {
					return walk(inner)
				}
			default:
				return false
			}
		}

		if multi, ok := e.(interface{ Unwrap() []error }); ok {
			for _, inner := range multi.Unwrap() {
				if !walk(inner) {
					return false
				}
			}
		} else if single, ok := e.(interface{ Unwrap() error }); ok {
			if inner := single.Unwrap(); inner != nil {
				if !walk(inner) {
					return false
				}
			}
		}

		return true
	}

	if !walk(err) {
		return false
	}

	return hasExpiration
}
