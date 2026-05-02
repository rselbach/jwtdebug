package verification

import (
	"errors"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rselbach/jwtdebug/internal/constants"
)

var validAlgorithms []string

type keyParser func([]byte) (any, error)

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

func init() {
	for alg := range keyParsers {
		validAlgorithms = append(validAlgorithms, alg)
	}
}

const minHMACKeyLen = 32

func parseHMACKey(keyData []byte) (any, error) {
	if len(keyData) < minHMACKeyLen {
		return nil, fmt.Errorf("HMAC key too short: %d bytes (minimum %d)", len(keyData), minHMACKeyLen)
	}
	return keyData, nil
}

func parseRSAPublicKey(keyData []byte) (any, error) {
	return jwt.ParseRSAPublicKeyFromPEM(keyData)
}

func parseECPublicKey(keyData []byte) (any, error) {
	return jwt.ParseECPublicKeyFromPEM(keyData)
}

func parseEdPublicKey(keyData []byte) (any, error) {
	return jwt.ParseEdPublicKeyFromPEM(keyData)
}

// VerifyTokenSignature verifies the token signature using the provided key file
func VerifyTokenSignature(tokenString, keyFile string, ignoreExpiration bool) error {
	if keyFile == "" {
		return errors.New("key file not provided (--key-file / -k required)")
	}

	stat, err := os.Stat(keyFile)
	if err != nil {
		return fmt.Errorf("failed to stat key file: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return errors.New("key file must be a regular file")
	}

	if stat.Size() > constants.MaxFileSizeBytes {
		return fmt.Errorf("key file too large (max %d bytes)", constants.MaxFileSizeBytes)
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	parseOpts := []jwt.ParserOption{jwt.WithValidMethods(validAlgorithms)}

	_, err = jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		parser, ok := keyParsers[token.Method.Alg()]
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return parser(keyData)
	}, parseOpts...)

	if err != nil && ignoreExpiration && onlyTimeValidationErrors(err) {
		return nil
	}

	return err
}

var nonTimeValidationErrors = []error{
	jwt.ErrTokenSignatureInvalid,
	jwt.ErrTokenMalformed,
	jwt.ErrTokenUnverifiable,
	jwt.ErrTokenRequiredClaimMissing,
	jwt.ErrTokenInvalidAudience,
	jwt.ErrTokenInvalidIssuer,
	jwt.ErrTokenInvalidSubject,
	jwt.ErrTokenInvalidId,
	jwt.ErrTokenUsedBeforeIssued,
}

func onlyTimeValidationErrors(err error) bool {
	if err == nil {
		return false
	}

	hasTime := errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet)
	if !hasTime {
		return false
	}

	for _, e := range nonTimeValidationErrors {
		if errors.Is(err, e) {
			return false
		}
	}

	return true
}
