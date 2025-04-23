package printer

import (
	"encoding/json"
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
		var expTime int64
		
		switch v := exp.(type) {
		case float64:
			expTime = int64(v)
		case json.Number:
			expTime, _ = v.Int64()
		case int64:
			expTime = v
		case int:
			expTime = int64(v)
		default:
			fmt.Printf("Unknown expiration type: %T\n", exp)
			return
		}
		
		expTimeFormatted := time.Unix(expTime, 0).Format(time.RFC3339)
		
		if now > expTime {
			color.Red("✗ Token expired at %s (%.0f seconds ago)", 
				expTimeFormatted, float64(now-expTime))
		} else {
			color.Green("✓ Token expires at %s (%.0f seconds from now)", 
				expTimeFormatted, float64(expTime-now))
		}
	} else {
		fmt.Println("No expiration claim found")
	}

	// check for "nbf" (not before) claim
	if nbf, ok := claims["nbf"]; ok {
		var nbfTime int64
		
		switch v := nbf.(type) {
		case float64:
			nbfTime = int64(v)
		case json.Number:
			nbfTime, _ = v.Int64()
		case int64:
			nbfTime = v
		case int:
			nbfTime = int64(v)
		default:
			fmt.Println("Unknown notBefore type")
			return
		}
		
		nbfTimeFormatted := time.Unix(nbfTime, 0).Format(time.RFC3339)
		
		if now < nbfTime {
			color.Yellow("⚠ Token not valid yet. Valid from %s (in %.0f seconds)", 
				nbfTimeFormatted, float64(nbfTime-now))
		} else {
			color.Green("✓ Token valid since %s (%.0f seconds ago)", 
				nbfTimeFormatted, float64(now-nbfTime))
		}
	}

	// check for "iat" (issued at) claim
	if iat, ok := claims["iat"]; ok {
		var iatTime int64
		
		switch v := iat.(type) {
		case float64:
			iatTime = int64(v)
		case json.Number:
			iatTime, _ = v.Int64()
		case int64:
			iatTime = v
		case int:
			iatTime = int64(v)
		default:
			fmt.Println("Unknown issuedAt type")
			return
		}
		
		iatTimeFormatted := time.Unix(iatTime, 0).Format(time.RFC3339)
		fmt.Printf("Issued at: %s (%.0f seconds ago)\n", 
			iatTimeFormatted, float64(now-iatTime))
	}

	fmt.Println()
}
