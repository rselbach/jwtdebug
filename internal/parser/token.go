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
	tokenString = NormalizeTokenString(tokenString)
	// split the token into parts for analysis
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format: expected 3 parts, got %d", len(parts))
	}

	// parse without verification first using ParseUnverified
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("error parsing token: %w", err)
	}

	// show an unverified notice when not verifying (stderr; does not break JSON)
	if !cli.VerifySignature {
		printer.PrintUnverifiedNotice()
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
