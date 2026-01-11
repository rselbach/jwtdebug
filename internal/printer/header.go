package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

// PrintHeader prints the token header
func PrintHeader(token *jwt.Token) {
	headerTitle := color.New(color.FgBlue, color.Bold)
	printSection("HEADER:", headerTitle, func() {
		// For pretty format, print in aligned key-value format
		printPrettyHeader(token.Header)
	}, token.Header)
}

// printPrettyHeader prints the header in a nicely formatted and aligned way
func printPrettyHeader(header map[string]interface{}) {
	if len(header) == 0 {
		fmt.Println("  No header information available")
		return
	}

	// Get the keys and find the longest key for alignment
	var keys []string
	maxKeyLen := 0
	for k := range header {
		keys = append(keys, k)
		if len(k) > maxKeyLen {
			maxKeyLen = len(k)
		}
	}
	sort.Strings(keys)

	// Print each key-value pair with proper alignment
	keyColor := color.New(color.FgCyan).SprintFunc()
	for _, k := range keys {
		// Pad the key name for alignment (sanitize key name too)
		sanitizedKey := sanitizeString(k)
		paddedKey := fmt.Sprintf("  %s:%s", keyColor(sanitizedKey), strings.Repeat(" ", maxKeyLen-len(k)+1))
		// sanitize all values, not just strings
		fmt.Printf("%s%s\n", paddedKey, formatValue(header[k]))
	}
}
