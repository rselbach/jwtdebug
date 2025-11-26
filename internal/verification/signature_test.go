package verification

import (
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/stretchr/testify/require"
)

func TestVerifyTokenSignature(t *testing.T) {
	r := require.New(t)

	hmacKeyFile, err := os.CreateTemp("", "hmac_key_*.txt")
	r.NoError(err)
	t.Cleanup(func() { _ = os.Remove(hmacKeyFile.Name()) })

	hmacKey := "your-256-bit-secret"
	_, err = hmacKeyFile.WriteString(hmacKey)
	r.NoError(err)
	r.NoError(hmacKeyFile.Close())

	keyDir, err := os.MkdirTemp("", "jwtdebug-keydir")
	r.NoError(err)
	t.Cleanup(func() { _ = os.RemoveAll(keyDir) })

	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	now := time.Now()
	sign := func(claims jwt.MapClaims) string {
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, signErr := tok.SignedString([]byte(hmacKey))
		r.NoError(signErr)
		return signed
	}

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
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			prevKeyFile := cli.KeyFile
			prevIgnore := cli.IgnoreExpiration
			cli.KeyFile = tc.keyFile
			cli.IgnoreExpiration = tc.ignoreExpiration
			t.Cleanup(func() {
				cli.KeyFile = prevKeyFile
				cli.IgnoreExpiration = prevIgnore
			})

			err := VerifyTokenSignature(tc.token)

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
