package verification

import (
	"os"
	"strings"
	"testing"

	"github.com/rselbach/jwtdebug/internal/cli"
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

	// Test cases
	tests := []struct {
		name         string
		token        string
		keyFile      string
		expectError  bool
		errorMessage string
	}{
		{
			name:        "Valid token with correct key",
			token:       validToken,
			keyFile:     hmacKeyFile.Name(),
			expectError: false,
		},
		{
			name:         "Invalid token with correct key",
			token:        invalidToken,
			keyFile:      hmacKeyFile.Name(),
			expectError:  true,
			errorMessage: "signature is invalid",
		},
		{
			name:         "No key file provided",
			token:        validToken,
			keyFile:      "",
			expectError:  true,
			errorMessage: "key file not provided",
		},
		{
			name:         "Non-existent key file",
			token:        validToken,
			keyFile:      "non_existent_file.key",
			expectError:  true,
			errorMessage: "failed to read key file",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up the test
			cli.KeyFile = tt.keyFile
			
			// Call the function
			err := VerifyTokenSignature(tt.token)
			
			// Check the result
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMessage != "" && !strings.Contains(err.Error(), tt.errorMessage) {
					t.Errorf("Error message doesn't contain expected text.\nExpected: %s\nGot: %s", 
						tt.errorMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}
