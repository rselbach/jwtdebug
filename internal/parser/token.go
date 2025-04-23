package parser

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	
	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/printer"
	"github.com/rselbach/jwtdebug/internal/verification"
)

// ProcessToken parses and displays information about a JWT token
func ProcessToken(tokenString string) error {
	// split the token into parts for analysis
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
	}

	// parse without verification first
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// return a dummy key since we're not verifying yet
		return []byte("dummy"), nil
	}, jwt.WithoutClaimsValidation())

	// we expect this error since we're not verifying
	if err != nil && !cli.VerifySignature {
		// for jwt/v5, we need to check the error differently
		if !strings.Contains(err.Error(), "signature is invalid") {
			return fmt.Errorf("error parsing token: %w", err)
		}
	}

	// print token header
	if cli.WithHeader {
		printer.PrintHeader(token)
	}

	// print token claims
	if cli.WithClaims {
		printer.PrintClaims(token)
	}

	// print signature info
	if cli.WithSignature {
		printer.PrintSignature(parts[2])
	}

	// check expiration
	if cli.ShowExpiration {
		printer.CheckExpiration(token)
	}

	// verify signature if requested
	if cli.VerifySignature {
		if err := verification.VerifyTokenSignature(tokenString); err != nil {
			printer.PrintVerificationFailure(err)
		} else {
			printer.PrintVerificationSuccess()
		}
	}

	return nil
}
