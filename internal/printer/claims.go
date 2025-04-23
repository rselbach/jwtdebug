package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	
	"github.com/rselbach/jwtdebug/internal/cli"
)

// PrintClaims prints the token claims in the requested format
func PrintClaims(token *jwt.Token) {
	claimsTitle := color.New(color.FgGreen, color.Bold).SprintFunc()
	fmt.Println(claimsTitle("CLAIMS:"))
	
	// get claims as map
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("Could not extract claims")
		return
	}
	
	// Use the selected format (json, yaml, raw, or pretty)
	if cli.OutputFormat == "pretty" || cli.OutputFormat == "" {
		printPrettyClaims(claims)
	} else {
		fmt.Println(FormatData(claims))
		fmt.Println()
	}
}

// printPrettyClaims prints claims in a human-friendly format with improved formatting
func printPrettyClaims(claims jwt.MapClaims) {
	// convert to a sorted list of keys for consistent output
	var standardKeys []string
	var customKeys []string
	
	// special handling for standard JWT claims
	standardClaims := map[string]string{
		"sub": "Subject",
		"iss": "Issuer",
		"aud": "Audience",
		"exp": "Expiration",
		"nbf": "Not Before",
		"iat": "Issued At",
		"jti": "JWT ID",
	}
	
	// Standard order for standard claims
	standardOrder := []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}
	
	// Find max key length for alignment (use same for both sections)
	maxKeyLen := 0
	
	// Organize keys and find max length
	for key := range claims {
		if _, ok := standardClaims[key]; ok {
			standardKeys = append(standardKeys, key)
			displayName := standardClaims[key]
			if len(displayName) > maxKeyLen {
				maxKeyLen = len(displayName)
			}
		} else {
			customKeys = append(customKeys, key)
			if len(key) > maxKeyLen {
				maxKeyLen = len(key)
			}
		}
	}
	sort.Strings(standardKeys)
	sort.Strings(customKeys)
	
	// Standard claim section title
	sectionTitleColor := color.New(color.FgGreen, color.Bold).SprintFunc()
	keyColor := color.New(color.FgCyan).SprintFunc()
	
	// Only print standard claims section if there are any
	if len(standardKeys) > 0 {
		fmt.Println(sectionTitleColor("  Standard Claims:"))
		
		// Print standard claims in the preferred order
		for _, preferred := range standardOrder {
			found := false
			for _, key := range standardKeys {
				if key == preferred {
					found = true
					break
				}
			}
			
			if found {
				// Get display name and pad for alignment
				displayKey := standardClaims[preferred]
				paddedKey := fmt.Sprintf("    %s:%s", keyColor(displayKey), strings.Repeat(" ", maxKeyLen-len(displayKey)+1))
				
				val := claims[preferred]
				
				// Special handling for time fields
				if preferred == "exp" || preferred == "nbf" || preferred == "iat" {
					if formattedTime, isTime := formatTimestamp(val); isTime {
						fmt.Printf("%s%s\n", paddedKey, formattedTime)
					} else {
						fmt.Printf("%s%v\n", paddedKey, formatValue(val))
					}
				} else {
					fmt.Printf("%s%v\n", paddedKey, formatValue(val))
				}
			}
		}
	}
	
	// Print custom claims section if there are any
	if len(customKeys) > 0 {
		// Add spacing if we had standard claims
		if len(standardKeys) > 0 {
			fmt.Println()
		}
		
		fmt.Println(sectionTitleColor("  Custom Claims:"))
		for _, key := range customKeys {
			paddedKey := fmt.Sprintf("    %s:%s", keyColor(key), strings.Repeat(" ", maxKeyLen-len(key)+1))
			
			// Try to parse custom claim as a timestamp
			if formattedTime, isTime := formatTimestamp(claims[key]); isTime {
				fmt.Printf("%s%s\n", paddedKey, formattedTime)
			} else {
				fmt.Printf("%s%v\n", paddedKey, formatValue(claims[key]))
			}
		}
	}
	
	fmt.Println()
}
