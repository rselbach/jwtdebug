package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

// PrintClaims prints the token claims in the requested format
func PrintClaims(token *jwt.Token, outputFormat string) {
	claimsTitle := color.New(color.FgGreen, color.Bold)

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println(claimsTitle.Sprint("CLAIMS:"))
		fmt.Println("Could not extract claims")
		return
	}

	printSection("CLAIMS:", claimsTitle, func() {
		printPrettyClaims(claims)
	}, claims, outputFormat)
}

func formatClaimValue(value any, tryTimestamp bool) string {
	if tryTimestamp {
		if formattedTime, ok := formatTimestamp(value); ok {
			return formattedTime
		}
	}
	return formatValue(value)
}

func isStandardTimestampClaim(name string) bool {
	return name == "exp" || name == "nbf" || name == "iat"
}

func printPrettyClaims(claims jwt.MapClaims) {
	standardClaims := map[string]string{
		"sub": "Subject",
		"iss": "Issuer",
		"aud": "Audience",
		"exp": "Expiration",
		"nbf": "Not Before",
		"iat": "Issued At",
		"jti": "JWT ID",
	}

	standardOrder := []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

	standardPresent := make(map[string]bool)
	var customKeys []string

	maxKeyLen := 0

	for key := range claims {
		if displayName, ok := standardClaims[key]; ok {
			standardPresent[key] = true
			if len(displayName) > maxKeyLen {
				maxKeyLen = len(displayName)
			}
			continue
		}

		customKeys = append(customKeys, key)
		if len(key) > maxKeyLen {
			maxKeyLen = len(key)
		}
	}
	sort.Strings(customKeys)

	sectionTitleColor := color.New(color.FgGreen, color.Bold).SprintFunc()
	keyColor := color.New(color.FgCyan).SprintFunc()

	if len(standardPresent) > 0 {
		fmt.Println(sectionTitleColor("  Standard Claims:"))

		for _, preferred := range standardOrder {
			if !standardPresent[preferred] {
				continue
			}

			displayKey := standardClaims[preferred]
			paddedKey := fmt.Sprintf("    %s:%s", keyColor(displayKey), strings.Repeat(" ", maxKeyLen-len(displayKey)+1))

			val := claims[preferred]
			formattedValue := formatClaimValue(val, isStandardTimestampClaim(preferred))
			fmt.Printf("%s%v\n", paddedKey, formattedValue)
		}
	}

	if len(customKeys) > 0 {
		if len(standardPresent) > 0 {
			fmt.Println()
		}

		fmt.Println(sectionTitleColor("  Custom Claims:"))
		for _, key := range customKeys {
			paddedKey := fmt.Sprintf("    %s:%s", keyColor(key), strings.Repeat(" ", maxKeyLen-len(key)+1))

			formattedValue := formatClaimValue(claims[key], true)
			fmt.Printf("%s%v\n", paddedKey, formattedValue)
		}
	}
}
