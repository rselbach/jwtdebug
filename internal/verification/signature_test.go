package verification

import (
	"os"
	"testing"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/stretchr/testify/require"
)

func TestVerifyTokenSignature(t *testing.T) {
	// Create temporary files for testing
	hmacKeyFile, err := os.CreateTemp("", "hmac_key_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(hmacKeyFile.Name())

	// Write test key to file
	hmacKey := "your-256-bit-secret"
	if _, err := hmacKeyFile.WriteString(hmacKey); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	hmacKeyFile.Close()

	// Valid token signed with the test key
	validToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Invalid token (payload modified)
	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUgRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	// Create a directory to test non-regular file handling
	keyDir, err := os.MkdirTemp("", "jwtdebug-keydir")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(keyDir)

	// test cases
	tests := map[string]struct {
		token        string
		keyFile      string
		expectError  bool
		errorMessage string
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
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			// set up the test
			cli.KeyFile = tc.keyFile

			// call the function
			err := VerifyTokenSignature(tc.token)

			// check the result
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
