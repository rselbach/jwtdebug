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
		"Malformed base64 in header": {
			token:      "!!!invalid-base64!!!.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
			shouldFail: true,
		},
		"Malformed base64 in payload": {
			token:      "eyJhbGciOiJIUzI1NiJ9.!!!invalid-base64!!!.signature",
			shouldFail: true,
		},
		"Token with unusual but valid claims": {
			token:      "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuZXN0ZWQiOnsia2V5IjoidmFsdWUifSwiYXJyYXkiOlsxLDIsM10sImVtcHR5Ijp7fX0.",
			shouldFail: false,
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
	tests := map[string]struct {
		in   string
		want string
	}{
		"bearer with extra spaces": {
			in:   "  Bearer    abc.def.ghi ",
			want: "abc.def.ghi",
		},
		"lowercase bearer": {
			in:   "bearer abc.def.ghi",
			want: "abc.def.ghi",
		},
		"uppercase bearer": {
			in:   "BEARER abc.def.ghi",
			want: "abc.def.ghi",
		},
		"token without bearer": {
			in:   "token.only",
			want: "token.only",
		},
		"bearer without space": {
			in:   "bearerabc.def.ghi",
			want: "bearerabc.def.ghi",
		},
		"whitespace only": {
			in:   "   ",
			want: "",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got := NormalizeTokenString(tc.in)
			r.Equal(tc.want, got)
		})
	}
}
