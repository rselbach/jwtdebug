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
func ProcessToken(tokenString string, f *cli.Flags) Result {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		snippet := tokenSnippet(tokenString)
		return Result{
			ExitCode: constants.ExitInvalidToken,
			Err:      fmt.Errorf("invalid token format: expected 3 parts separated by '.', got %d (token: %s)", len(parts), snippet),
		}
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		snippet := tokenSnippet(tokenString)
		return Result{
			ExitCode: constants.ExitInvalidToken,
			Err:      fmt.Errorf("failed to parse token (%s): %w", snippet, err),
		}
	}

	if f.RawClaims {
		return outputRawClaims(token)
	}

	if !f.VerifySignature {
		printer.PrintUnverifiedNotice(f.Quiet)
	}

	if f.WithHeader {
		printer.PrintHeader(token, f.OutputFormat)
	}

	if f.WithClaims {
		printer.PrintClaims(token, f.OutputFormat)
	}

	if f.WithSignature {
		printer.PrintSignature(parts[2], f.OutputFormat, f.DecodeBase64)
	}

	if f.ShowExpiration {
		printer.CheckExpiration(token)
	}

	if f.VerifySignature {
		if err := verification.VerifyTokenSignature(tokenString, f.KeyFile, f.IgnoreExpiration); err != nil {
			printer.PrintVerificationFailure(err)
			return Result{
				ExitCode: constants.ExitVerificationFail,
				Err:      nil,
			}
		}
		printer.PrintVerificationSuccess()
	}

	return Result{ExitCode: constants.ExitSuccess}
}

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

func tokenSnippet(token string) string {
	if len(token) <= 20 {
		return token
	}
	return token[:17] + "..."
}
