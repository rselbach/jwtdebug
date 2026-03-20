package verification

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stretchr/testify/require"
)

func TestVerifyTokenSignature(t *testing.T) {
	r := require.New(t)

	hmacKeyFile, err := os.CreateTemp("", "hmac_key_*.txt")
	r.NoError(err)
	t.Cleanup(func() {
		err := os.Remove(hmacKeyFile.Name())
		if err == nil {
			return
		}
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		t.Errorf("failed to remove temp key file %q: %v", hmacKeyFile.Name(), err)
	})

	hmacKey := "your-256-bit-secret-with-enough-bytes!"
	_, err = hmacKeyFile.WriteString(hmacKey)
	r.NoError(err)
	r.NoError(hmacKeyFile.Close())

	keyDir, err := os.MkdirTemp("", "jwtdebug-keydir")
	r.NoError(err)
	t.Cleanup(func() {
		err := os.RemoveAll(keyDir)
		if err == nil {
			return
		}
		t.Errorf("failed to remove temp key dir %q: %v", keyDir, err)
	})

	now := time.Now()
	sign := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, signErr := tok.SignedString([]byte(hmacKey))
		r.NoError(signErr)
		return signed
	}

	validClaims := jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"iat":  now.Add(-time.Hour).Unix(),
		"exp":  now.Add(time.Hour).Unix(),
	}
	validToken := sign(validClaims)

	// Same header+payload but wrong signature
	invalidToken := sign(validClaims) + "tampered"

	expiredToken := sign(jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"exp":  now.Add(-time.Hour).Unix(),
		"nbf":  now.Add(-2 * time.Hour).Unix(),
	})

	notYetValidToken := sign(jwt.MapClaims{
		"sub":  "1234567890",
		"name": "John Doe",
		"nbf":  now.Add(time.Hour).Unix(),
		"exp":  now.Add(2 * time.Hour).Unix(),
	})

	shortKeyFile, err := os.CreateTemp("", "short_key_*.txt")
	r.NoError(err)
	_, err = shortKeyFile.WriteString("short")
	r.NoError(err)
	r.NoError(shortKeyFile.Close())
	t.Cleanup(func() { os.Remove(shortKeyFile.Name()) })

	tests := map[string]struct {
		token            string
		keyFile          string
		ignoreExpiration bool
		expectError      bool
		errorMessage     string
	}{
		"Valid token with correct key": {
			token:       validToken,
			keyFile:     hmacKeyFile.Name(),
			expectError: false,
		},
		"Invalid token with correct key": {
			token:        invalidToken,
			keyFile:      hmacKeyFile.Name(),
			expectError:  true,
			errorMessage: "signature is invalid",
		},
		"No key file provided": {
			token:        validToken,
			keyFile:      "",
			expectError:  true,
			errorMessage: "key file not provided",
		},
		"Non-existent key file": {
			token:        validToken,
			keyFile:      "non_existent_file.key",
			expectError:  true,
			errorMessage: "failed to stat key file",
		},
		"Key file is not regular": {
			token:        validToken,
			keyFile:      keyDir,
			expectError:  true,
			errorMessage: "key file must be a regular file",
		},
		"Expired token fails when ignore-exp disabled": {
			token:        expiredToken,
			keyFile:      hmacKeyFile.Name(),
			expectError:  true,
			errorMessage: "token is expired",
		},
		"Expired token succeeds when ignore-exp enabled": {
			token:            expiredToken,
			keyFile:          hmacKeyFile.Name(),
			ignoreExpiration: true,
			expectError:      false,
		},
		"Token not yet valid succeeds with ignore-exp": {
			token:            notYetValidToken,
			keyFile:          hmacKeyFile.Name(),
			ignoreExpiration: true,
			expectError:      false,
		},
		"Short HMAC key rejected": {
			token:        validToken,
			keyFile:      shortKeyFile.Name(),
			expectError:  true,
			errorMessage: "HMAC key too short",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			err := VerifyTokenSignature(tc.token, tc.keyFile, tc.ignoreExpiration)

			if tc.expectError {
				r.Error(err, "Expected error but got none")
				if tc.errorMessage != "" {
					r.Contains(err.Error(), tc.errorMessage, "Error message doesn't contain expected text")
				}
			} else {
				r.NoError(err, "Expected no error")
			}
		})
	}
}
