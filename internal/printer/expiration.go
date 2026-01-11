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

	handleTimestampClaim(claims, "exp", func() {
		fmt.Println("No expiration claim found")
	}, func(value interface{}) {
		fmt.Printf("Unrecognized expiration value: %v\n", value)
	}, func(t time.Time) {
		expUnix := t.Unix()
		expTimeFormatted := t.Format(time.RFC3339)
		if now > expUnix {
			color.Red("✗ Token expired at %s (%.0f seconds ago)", expTimeFormatted, float64(now-expUnix))
			return
		}
		color.Green("✓ Token expires at %s (%.0f seconds from now)", expTimeFormatted, float64(expUnix-now))
	})

	handleTimestampClaim(claims, "nbf", nil, func(interface{}) {
		fmt.Println("Unrecognized notBefore value")
	}, func(t time.Time) {
		nbfUnix := t.Unix()
		nbfTimeFormatted := t.Format(time.RFC3339)
		if now < nbfUnix {
			color.Yellow("⚠ Token not valid yet. Valid from %s (in %.0f seconds)", nbfTimeFormatted, float64(nbfUnix-now))
			return
		}
		color.Green("✓ Token valid since %s (%.0f seconds ago)", nbfTimeFormatted, float64(now-nbfUnix))
	})

	handleTimestampClaim(claims, "iat", nil, func(interface{}) {
		fmt.Println("Unrecognized issuedAt value")
	}, func(t time.Time) {
		fmt.Printf("Issued at: %s (%.0f seconds ago)\n", t.Format(time.RFC3339), float64(now-t.Unix()))
	})

	fmt.Println()
}

func handleTimestampClaim(claims jwt.MapClaims, name string, onMissing func(), onInvalid func(interface{}), onValid func(time.Time)) {
	value, ok := claims[name]
	if !ok {
		if onMissing != nil {
			onMissing()
		}
		return
	}

	if t, ok := tryParseTimestamp(value); ok {
		onValid(t)
		return
	}

	if onInvalid != nil {
		onInvalid(value)
	}
}
