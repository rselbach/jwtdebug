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
			result := ProcessToken(tc.token)

			if tc.token == "" {
				r.NotNil(result.Err, "Expected an error for empty token")
				return
			}

			// Simulate token parsing
			if tc.shouldFail {
				r.NotNil(result.Err, "Expected an error for token: %s", tc.token)
			} else {
				r.Nil(result.Err, "Did not expect an error for valid token")
			}
		})
	}
}

func TestNormalizeTokenString(t *testing.T) {
	// Sample JWT-like tokens (valid base64url format)
	validJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.signature123"

	tests := map[string]struct {
		in   string
		want string
	}{
		"bearer prefix": {
			in:   "Bearer " + validJWT,
			want: validJWT,
		},
		"bearer with extra spaces": {
			in:   "  Bearer    " + validJWT + " ",
			want: validJWT,
		},
		"lowercase bearer": {
			in:   "bearer " + validJWT,
			want: validJWT,
		},
		"cookie format": {
			in:   "_auth_token=" + validJWT,
			want: validJWT,
		},
		"cookie with spaces": {
			in:   "  session_cookie = " + validJWT + "; HttpOnly",
			want: validJWT,
		},
		"authorization header": {
			in:   "Authorization: Bearer " + validJWT,
			want: validJWT,
		},
		"set-cookie header": {
			in:   "Set-Cookie: token=" + validJWT + "; Path=/; Secure",
			want: validJWT,
		},
		"json with token field": {
			in:   `{"access_token":"` + validJWT + `"}`,
			want: validJWT,
		},
		"raw jwt": {
			in:   validJWT,
			want: validJWT,
		},
		"jwt with whitespace": {
			in:   "  " + validJWT + "  ",
			want: validJWT,
		},
		"no jwt found returns original": {
			in:   "not.a.jwt",
			want: "not.a.jwt",
		},
		"whitespace only": {
			in:   "   ",
			want: "",
		},
		"empty string": {
			in:   "",
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
