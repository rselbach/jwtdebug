package verification

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/constants"
)

var validAlgorithms = []string{"HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}

type keyParser func([]byte) (interface{}, error)

var keyParsers = map[string]keyParser{
	"HS256": parseHMACKey,
	"HS384": parseHMACKey,
	"HS512": parseHMACKey,
	"RS256": parseRSAPublicKey,
	"RS384": parseRSAPublicKey,
	"RS512": parseRSAPublicKey,
	"PS256": parseRSAPublicKey,
	"PS384": parseRSAPublicKey,
	"PS512": parseRSAPublicKey,
	"ES256": parseECPublicKey,
	"ES384": parseECPublicKey,
	"ES512": parseECPublicKey,
	"EdDSA": parseEdPublicKey,
}

func parseHMACKey(keyData []byte) (interface{}, error) {
	return keyData, nil
}

func parseRSAPublicKey(keyData []byte) (interface{}, error) {
	return jwt.ParseRSAPublicKeyFromPEM(keyData)
}

func parseECPublicKey(keyData []byte) (interface{}, error) {
	return jwt.ParseECPublicKeyFromPEM(keyData)
}

func parseEdPublicKey(keyData []byte) (interface{}, error) {
	return jwt.ParseEdPublicKeyFromPEM(keyData)
}

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
	if stat.Size() > constants.MaxFileSizeBytes {
		return fmt.Errorf("key file too large (max %d bytes)", constants.MaxFileSizeBytes)
	}

	// read key file
	keyData, err := os.ReadFile(cli.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	// parse the token with verification
	parseOpts := []jwt.ParserOption{jwt.WithValidMethods(validAlgorithms)}

	// parse using the provided key
	_, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		parser, ok := keyParsers[token.Method.Alg()]
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return parser(keyData)
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
