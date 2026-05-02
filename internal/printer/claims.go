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

type claimMeta struct {
	name        string
	label       string
	isTimestamp bool
}

var standardClaims = []claimMeta{
	{"iss", "Issuer", false},
	{"sub", "Subject", false},
	{"aud", "Audience", false},
	{"exp", "Expiration", true},
	{"nbf", "Not Before", true},
	{"iat", "Issued At", true},
	{"jti", "JWT ID", false},
}

func printPrettyClaims(claims jwt.MapClaims) {
	// Build standard lines and collect all keys for max length calculation.
	var standardLines [][2]string
	allKeys := make([]string, 0, len(claims))
	for _, meta := range standardClaims {
		if val, ok := claims[meta.name]; ok {
			standardLines = append(standardLines, [2]string{meta.label, formatClaimValue(val, meta.isTimestamp)})
			allKeys = append(allKeys, meta.label)
		}
	}

	var customKeys []string
	standardSet := make(map[string]bool, len(standardClaims))
	for _, meta := range standardClaims {
		standardSet[meta.name] = true
	}
	for key := range claims {
		if !standardSet[key] {
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
