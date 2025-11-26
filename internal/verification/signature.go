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

	// limit key file size to prevent DoS
	const maxKeySize = 1024 * 1024 // 1MB
	if stat.Size() > maxKeySize {
		return errors.New("key file too large (max 1MB)")
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

	if err != nil && cli.IgnoreExpiration && onlyTimeValidationErrors(err) {
		return nil
	}

	return err
}

// onlyTimeValidationErrors reports whether the provided error (and any wrapped errors)
// consists exclusively of time-related validation failures (expired or not yet valid).
func onlyTimeValidationErrors(err error) bool {
	if err == nil {
		return false
	}

	hasTimeError := false

	// walk returns true if e (and all wrapped errors) are acceptable
	// (either time-related errors or allowed wrappers like ErrTokenInvalidClaims)
	var walk func(error) bool
	walk = func(e error) bool {
		if e == nil {
			return true
		}

		// check if this is directly a time-related sentinel
		if errors.Is(e, jwt.ErrTokenExpired) || errors.Is(e, jwt.ErrTokenNotValidYet) {
			hasTimeError = true
			return true
		}
		if errors.Is(e, jwt.ErrTokenInvalidClaims) {
			return true
		}

		// for any other error, we must unwrap and check children
		if multi, ok := e.(interface{ Unwrap() []error }); ok {
			for _, inner := range multi.Unwrap() {
				if !walk(inner) {
					return false
				}
			}
			return true
		}
		if single, ok := e.(interface{ Unwrap() error }); ok {
			if inner := single.Unwrap(); inner != nil {
				return walk(inner)
			}
			// wraps nil - this is a leaf that's not time-related
			return false
		}

		// leaf error that's not time-related
		return false
	}

	if !walk(err) {
		return false
	}

	return hasTimeError
}
