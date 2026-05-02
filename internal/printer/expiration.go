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

	printTimeClaim("exp", claims, func(t time.Time) {
		expUnix := t.Unix()
		if now > expUnix {
			color.Red("✗ Token expired at %s (%.0f seconds ago)", t.Format(time.RFC3339), float64(now-expUnix))
		} else {
			color.Green("✓ Token expires at %s (%.0f seconds from now)", t.Format(time.RFC3339), float64(expUnix-now))
		}
	}, func() {
		fmt.Println("No expiration claim found")
	})

	printTimeClaim("nbf", claims, func(t time.Time) {
		nbfUnix := t.Unix()
		if now < nbfUnix {
			color.Yellow("⚠ Token not valid yet. Valid from %s (in %.0f seconds)", t.Format(time.RFC3339), float64(nbfUnix-now))
		} else {
			color.Green("✓ Token valid since %s (%.0f seconds ago)", t.Format(time.RFC3339), float64(now-nbfUnix))
		}
	}, nil)

	printTimeClaim("iat", claims, func(t time.Time) {
		fmt.Printf("Issued at: %s (%.0f seconds ago)\n", t.Format(time.RFC3339), float64(now-t.Unix()))
	}, nil)

	fmt.Println()
}

func printTimeClaim(name string, claims jwt.MapClaims, onFound func(time.Time), onMissing func()) {
	if v, exists := claims[name]; exists {
		if t, ok := tryParseTimestamp(v); ok {
			onFound(t)
			return
		}
		fmt.Printf("Unrecognized %s value: %v\n", name, v)
		return
	}
	if onMissing != nil {
		onMissing()
	}
}
