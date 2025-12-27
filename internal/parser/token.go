package parser

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/constants"
	"github.com/rselbach/jwtdebug/internal/printer"
	"github.com/rselbach/jwtdebug/internal/verification"
)

// Result represents the outcome of processing a token
type Result struct {
	ExitCode int
	Err      error
}

// ProcessToken parses and displays information about a JWT token
func ProcessToken(tokenString string) Result {
	// split the token into parts for analysis
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		snippet := tokenSnippet(tokenString)
		return Result{
			ExitCode: constants.ExitInvalidToken,
			Err:      fmt.Errorf("invalid token format: expected 3 parts separated by '.', got %d (token: %s)", len(parts), snippet),
		}
	}

	// parse without verification first using ParseUnverified
	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		snippet := tokenSnippet(tokenString)
		return Result{
			ExitCode: constants.ExitInvalidToken,
			Err:      fmt.Errorf("failed to parse token (%s): %w", snippet, err),
		}
	}

	// handle --raw-claims mode: output only the claims JSON and exit
	if cli.RawClaims {
		return outputRawClaims(token)
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
			return Result{
				ExitCode: constants.ExitVerificationFail,
				Err:      nil, // error already printed
			}
		}
		printer.PrintVerificationSuccess()
	}

	return Result{ExitCode: constants.ExitSuccess}
}

// outputRawClaims outputs only the raw claims as JSON (for piping to jq, etc.)
func outputRawClaims(token *jwt.Token) Result {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return Result{
			ExitCode: constants.ExitInvalidToken,
			Err:      fmt.Errorf("could not extract claims from token"),
		}
	}

	data, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return Result{
			ExitCode: constants.ExitError,
			Err:      fmt.Errorf("failed to encode claims as JSON: %w", err),
		}
	}

	fmt.Println(string(data))
	return Result{ExitCode: constants.ExitSuccess}
}

// tokenSnippet returns a short snippet of the token for error messages
func tokenSnippet(token string) string {
	if len(token) <= 20 {
		return token
	}
	return token[:17] + "..."
}
