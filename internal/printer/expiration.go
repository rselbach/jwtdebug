package printer

import (
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

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

	// check for "exp" claim
	if exp, ok := claims["exp"]; ok {
		if t, ok := tryParseTimestamp(exp); ok {
			expUnix := t.Unix()
			expTimeFormatted := t.Format(time.RFC3339)
			if now > expUnix {
				color.Red("✗ Token expired at %s (%.0f seconds ago)", expTimeFormatted, float64(now-expUnix))
			} else {
				color.Green("✓ Token expires at %s (%.0f seconds from now)", expTimeFormatted, float64(expUnix-now))
			}
		} else {
			fmt.Printf("Unrecognized expiration value: %v\n", exp)
		}
	} else {
		fmt.Println("No expiration claim found")
	}

	// check for "nbf" (not before) claim
	if nbf, ok := claims["nbf"]; ok {
		if t, ok := tryParseTimestamp(nbf); ok {
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

	// check for "iat" (issued at) claim
	if iat, ok := claims["iat"]; ok {
		if t, ok := tryParseTimestamp(iat); ok {
			fmt.Printf("Issued at: %s (%.0f seconds ago)\n", t.Format(time.RFC3339), float64(now-t.Unix()))
		} else {
			fmt.Println("Unrecognized issuedAt value")
		}
	}

	fmt.Println()
}
