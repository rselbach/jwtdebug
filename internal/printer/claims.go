package printer

import (
	"fmt"
	"sort"

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

	// Build standard lines and collect all keys for max length calculation.
	var standardLines [][2]string
	allKeys := make([]string, 0, len(claims))
	for _, key := range standardOrder {
		if val, ok := claims[key]; ok {
			displayKey := standardClaims[key]
			standardLines = append(standardLines, [2]string{displayKey, formatClaimValue(val, isStandardTimestampClaim(key))})
			allKeys = append(allKeys, displayKey)
		}
	}

	var customKeys []string
	for key := range claims {
		if _, ok := standardClaims[key]; !ok {
			customKeys = append(customKeys, key)
			allKeys = append(allKeys, key)
		}
	}
	sort.Strings(customKeys)

	var customLines [][2]string
	for _, key := range customKeys {
		customLines = append(customLines, [2]string{key, formatClaimValue(claims[key], true)})
	}

	maxKeyLen := maxStringLength(allKeys)
	sectionTitleColor := color.New(color.FgGreen, color.Bold).SprintFunc()

	if len(standardLines) > 0 {
		fmt.Println(sectionTitleColor("  Standard Claims:"))
		printKeyValueLines(standardLines, 4, maxKeyLen)
	}

	if len(customLines) > 0 {
		if len(standardLines) > 0 {
			fmt.Println()
		}
		fmt.Println(sectionTitleColor("  Custom Claims:"))
		printKeyValueLines(customLines, 4, maxKeyLen)
	}
}
