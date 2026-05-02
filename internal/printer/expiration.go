package printer

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

// PrintVerificationSuccess prints a success message for signature verification
func PrintVerificationSuccess() {
	color.Green("✓ Signature verified successfully")
}

// PrintVerificationFailure prints a failure message for signature verification
func PrintVerificationFailure(err error) {
	color.Red("✗ Signature verification failed: %v", err)
}

// PrintUnverifiedNotice prints a single-line warning that claims are unverified.
func PrintUnverifiedNotice(quiet bool) {
	if quiet {
		return
	}
	notice := color.New(color.FgYellow).Sprintf("Note: claims are unverified. Use --verify --key-file to validate.")
	fmt.Fprintln(color.Error, notice)
}

// CheckExpiration checks and displays token expiration status
func CheckExpiration(token *jwt.Token) {
	expTitle := color.New(color.FgCyan, color.Bold).SprintFunc()
	fmt.Println(expTitle("EXPIRATION:"))

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Could not extract claims")
		return
	}

	now := time.Now().Unix()

	// exp
	if v, exists := claims["exp"]; exists {
		if t, ok := tryParseTimestamp(v); ok {
			expUnix := t.Unix()
			expTimeFormatted := t.Format(time.RFC3339)
			if now > expUnix {
				color.Red("✗ Token expired at %s (%.0f seconds ago)", expTimeFormatted, float64(now-expUnix))
			} else {
				color.Green("✓ Token expires at %s (%.0f seconds from now)", expTimeFormatted, float64(expUnix-now))
			}
		} else {
			fmt.Printf("Unrecognized expiration value: %v\n", v)
		}
	} else {
		fmt.Println("No expiration claim found")
	}

	// nbf
	if v, exists := claims["nbf"]; exists {
		if t, ok := tryParseTimestamp(v); ok {
			nbfUnix := t.Unix()
			nbfTimeFormatted := t.Format(time.RFC3339)
			if now < nbfUnix {
				color.Yellow("⚠ Token not valid yet. Valid from %s (in %.0f seconds)", nbfTimeFormatted, float64(nbfUnix-now))
			} else {
				color.Green("✓ Token valid since %s (%.0f seconds ago)", nbfTimeFormatted, float64(now-nbfUnix))
			}
		} else {
			fmt.Println("Unrecognized notBefore value")
		}
	}

	// iat
	if v, exists := claims["iat"]; exists {
		if t, ok := tryParseTimestamp(v); ok {
			fmt.Printf("Issued at: %s (%.0f seconds ago)\n", t.Format(time.RFC3339), float64(now-t.Unix()))
		} else {
			fmt.Println("Unrecognized issuedAt value")
		}
	}

	fmt.Println()
}
