package printer

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestPrintHeader(t *testing.T) {
	tests := map[string]struct {
		header       map[string]any
		outputFormat string
	}{
		"typical JWT header": {
			header: map[string]any{
				"alg": "RS256",
				"typ": "JWT",
			},
			outputFormat: "pretty",
		},
		"header with kid": {
			header: map[string]any{
				"alg": "RS256",
				"typ": "JWT",
				"kid": "key-id-123",
			},
			outputFormat: "pretty",
		},
		"header json format": {
			header: map[string]any{
				"alg": "HS256",
				"typ": "JWT",
			},
			outputFormat: "json",
		},
		"header raw format": {
			header: map[string]any{
				"alg": "ES256",
				"typ": "JWT",
			},
			outputFormat: "raw",
		},
		"empty header": {
			header:       map[string]any{},
			outputFormat: "pretty",
		},
		"header with extra fields": {
			header: map[string]any{
				"alg":      "RS512",
				"typ":      "JWT",
				"kid":      "my-key",
				"x5u":      "https://example.com/cert",
				"cty":      "JWT",
				"crit":     []any{"exp"},
				"jku":      "https://example.com/jwks",
				"x5t":      "thumbprint",
				"x5c":      []any{"cert1", "cert2"},
				"x5t#S256": "sha256-thumbprint",
			},
			outputFormat: "pretty",
		},
		"header with numeric values": {
			header: map[string]any{
				"alg":     "RS256",
				"version": float64(2),
			},
			outputFormat: "pretty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			token := &jwt.Token{
				Header: tc.header,
			}

			r.NotPanics(func() {
				PrintHeader(token, tc.outputFormat)
			})
		})
	}
}

func TestPrintPrettyHeader(t *testing.T) {
	tests := map[string]struct {
		header map[string]any
	}{
		"empty header": {
			header: map[string]any{},
		},
		"single field": {
			header: map[string]any{
				"alg": "HS256",
			},
		},
		"multiple fields": {
			header: map[string]any{
				"alg": "RS256",
				"typ": "JWT",
				"kid": "key-123",
			},
		},
		"long key names": {
			header: map[string]any{
				"algorithm":      "RS256",
				"type":           "JWT",
				"key_identifier": "key-123",
			},
		},
		"special characters in values": {
			header: map[string]any{
				"alg": "RS256",
				"kid": "key/with/slashes",
				"x5u": "https://example.com/cert?id=123&type=x509",
			},
		},
		"array values": {
			header: map[string]any{
				"crit": []any{"exp", "nbf"},
				"x5c":  []any{"cert1", "cert2", "cert3"},
			},
		},
		"nil value": {
			header: map[string]any{
				"alg":      "RS256",
				"optional": nil,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			r.NotPanics(func() {
				printPrettyHeader(tc.header)
			})
		})
	}
}
