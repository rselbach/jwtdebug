package printer

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/rselbach/jwtdebug/internal/cli"
)

func TestPrintClaims(t *testing.T) {
	tests := map[string]struct {
		claims       jwt.MapClaims
		outputFormat string
	}{
		"standard claims only": {
			claims: jwt.MapClaims{
				"iss": "test-issuer",
				"sub": "user123",
				"aud": "test-audience",
				"exp": float64(1735344000),
				"iat": float64(1735257600),
			},
			outputFormat: "pretty",
		},
		"custom claims only": {
			claims: jwt.MapClaims{
				"user_id": "abc123",
				"role":    "admin",
				"scopes":  []interface{}{"read", "write"},
			},
			outputFormat: "pretty",
		},
		"mixed claims": {
			claims: jwt.MapClaims{
				"iss":     "test-issuer",
				"sub":     "user123",
				"exp":     float64(1735344000),
				"user_id": "abc123",
				"role":    "admin",
			},
			outputFormat: "pretty",
		},
		"json format": {
			claims: jwt.MapClaims{
				"iss":     "test-issuer",
				"user_id": "abc123",
			},
			outputFormat: "json",
		},
		"raw format": {
			claims: jwt.MapClaims{
				"iss": "test-issuer",
				"sub": "user123",
			},
			outputFormat: "raw",
		},
		"empty claims": {
			claims:       jwt.MapClaims{},
			outputFormat: "pretty",
		},
		"nested claims": {
			claims: jwt.MapClaims{
				"user": map[string]interface{}{
					"name":  "John",
					"email": "john@example.com",
				},
			},
			outputFormat: "pretty",
		},
		"all standard claims": {
			claims: jwt.MapClaims{
				"iss": "issuer",
				"sub": "subject",
				"aud": "audience",
				"exp": float64(1735344000),
				"nbf": float64(1735257600),
				"iat": float64(1735257600),
				"jti": "unique-id-123",
			},
			outputFormat: "pretty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			// Reset cli flags
			cli.OutputFormat = tc.outputFormat

			token := &jwt.Token{
				Claims: tc.claims,
			}

			// Test that PrintClaims doesn't panic
			r.NotPanics(func() {
				PrintClaims(token)
			})
		})
	}
}

func TestPrintClaimsWithInvalidClaims(t *testing.T) {
	r := require.New(t)

	cli.OutputFormat = "pretty"

	// Create a token with non-MapClaims type
	token := &jwt.Token{
		Claims: jwt.RegisteredClaims{
			Issuer:  "test",
			Subject: "user",
		},
	}

	// Should not panic, just print error message
	r.NotPanics(func() {
		PrintClaims(token)
	})
}

func TestPrintPrettyClaims(t *testing.T) {
	tests := map[string]struct {
		claims jwt.MapClaims
	}{
		"with timestamp values": {
			claims: jwt.MapClaims{
				"exp":        float64(1735344000),
				"nbf":        float64(1735257600),
				"iat":        float64(1735257600),
				"custom_exp": float64(1735344000),
			},
		},
		"with array values": {
			claims: jwt.MapClaims{
				"aud":    []interface{}{"aud1", "aud2"},
				"scopes": []interface{}{"read", "write", "delete"},
			},
		},
		"with boolean values": {
			claims: jwt.MapClaims{
				"verified": true,
				"admin":    false,
			},
		},
		"with numeric values": {
			claims: jwt.MapClaims{
				"count":  float64(42),
				"rating": float64(4.5),
			},
		},
		"empty claims": {
			claims: jwt.MapClaims{},
		},
		"only custom claims": {
			claims: jwt.MapClaims{
				"custom1": "value1",
				"custom2": "value2",
			},
		},
		"only standard claims": {
			claims: jwt.MapClaims{
				"iss": "issuer",
				"sub": "subject",
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			r.NotPanics(func() {
				printPrettyClaims(tc.claims)
			})
		})
	}
}
