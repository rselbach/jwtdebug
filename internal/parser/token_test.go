package parser

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProcessToken(t *testing.T) {
	tests := map[string]struct {
		token        string
		shouldFail   bool
		errorMessage string
	}{
		"Valid Token": {
			// Use a base64url-encoded signature so parsing works without verification
			token:      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl",
			shouldFail: false,
		},
		"Empty Token": {
			token:        "",
			shouldFail:   true,
			errorMessage: "invalid token format",
		},
		"Malformed Token": {
			token:        "invalid.token",
			shouldFail:   true,
			errorMessage: "invalid token format",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			err := ProcessToken(tc.token)

			if tc.token == "" {
				r.Error(err, "Expected an error for empty token")
				return
			}

			// Simulate token parsing
			if tc.shouldFail {
				r.Error(err, "Expected an error for token: %s", tc.token)
			} else {
				r.NoError(err, "Did not expect an error for valid token")
			}
		})
	}
}

func TestNormalizeTokenString(t *testing.T) {
	cases := []struct {
		in  string
		out string
	}{
		{"  Bearer    abc.def.ghi ", "abc.def.ghi"},
		{"bearer abc.def.ghi", "abc.def.ghi"},
		{"BEARER abc.def.ghi", "abc.def.ghi"},
		{"token.only", "token.only"},
		{"bearerabc.def.ghi", "bearerabc.def.ghi"},
		{"   ", ""},
	}
	for _, c := range cases {
		got := NormalizeTokenString(c.in)
		if got != c.out {
			t.Fatalf("NormalizeTokenString(%q) => %q, want %q", c.in, got, c.out)
		}
	}
}
