package printer

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/rselbach/jwtdebug/internal/cli"
)

func TestPrintHeader(t *testing.T) {
	tests := map[string]struct {
		header       map[string]interface{}
		outputFormat string
	}{
		"typical JWT header": {
			header: map[string]interface{}{
				"alg": "RS256",
				"typ": "JWT",
			},
			outputFormat: "pretty",
		},
		"header with kid": {
			header: map[string]interface{}{
				"alg": "RS256",
				"typ": "JWT",
				"kid": "key-id-123",
			},
			outputFormat: "pretty",
		},
		"header json format": {
			header: map[string]interface{}{
				"alg": "HS256",
				"typ": "JWT",
			},
			outputFormat: "json",
		},
		"header raw format": {
			header: map[string]interface{}{
				"alg": "ES256",
				"typ": "JWT",
			},
			outputFormat: "raw",
		},
		"empty header": {
			header:       map[string]interface{}{},
			outputFormat: "pretty",
		},
		"header with extra fields": {
			header: map[string]interface{}{
				"alg":   "RS512",
				"typ":   "JWT",
				"kid":   "my-key",
				"x5u":   "https://example.com/cert",
				"cty":   "JWT",
				"crit":  []interface{}{"exp"},
				"jku":   "https://example.com/jwks",
				"x5t":   "thumbprint",
				"x5c":   []interface{}{"cert1", "cert2"},
				"x5t#S256": "sha256-thumbprint",
			},
			outputFormat: "pretty",
		},
		"header with numeric values": {
			header: map[string]interface{}{
				"alg":     "RS256",
				"version": float64(2),
			},
			outputFormat: "pretty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			cli.OutputFormat = tc.outputFormat

			token := &jwt.Token{
				Header: tc.header,
			}

			r.NotPanics(func() {
				PrintHeader(token)
			})
		})
	}
}

func TestPrintPrettyHeader(t *testing.T) {
	tests := map[string]struct {
		header map[string]interface{}
	}{
		"empty header": {
			header: map[string]interface{}{},
		},
		"single field": {
			header: map[string]interface{}{
				"alg": "HS256",
			},
		},
		"multiple fields": {
			header: map[string]interface{}{
				"alg": "RS256",
				"typ": "JWT",
				"kid": "key-123",
			},
		},
		"long key names": {
			header: map[string]interface{}{
				"algorithm":      "RS256",
				"type":           "JWT",
				"key_identifier": "key-123",
			},
		},
		"special characters in values": {
			header: map[string]interface{}{
				"alg": "RS256",
				"kid": "key/with/slashes",
				"x5u": "https://example.com/cert?id=123&type=x509",
			},
		},
		"array values": {
			header: map[string]interface{}{
				"crit": []interface{}{"exp", "nbf"},
				"x5c":  []interface{}{"cert1", "cert2", "cert3"},
			},
		},
		"nil value": {
			header: map[string]interface{}{
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
