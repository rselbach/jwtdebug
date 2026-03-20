package printer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

// PrintHeader prints the token header
func PrintHeader(token *jwt.Token, outputFormat string) {
	headerTitle := color.New(color.FgBlue, color.Bold)
	printSection("HEADER:", headerTitle, func() {
		printPrettyHeader(token.Header)
	}, token.Header, outputFormat)
}

func printPrettyHeader(header map[string]any) {
	if len(header) == 0 {
		fmt.Println("  No header information available")
		return
	}

	var keys []string
	maxKeyLen := 0
	for k := range header {
		keys = append(keys, k)
		if len(k) > maxKeyLen {
			maxKeyLen = len(k)
		}
	}
	sort.Strings(keys)

	keyColor := color.New(color.FgCyan).SprintFunc()
	for _, k := range keys {
		sanitizedKey := sanitizeString(k)
		paddedKey := fmt.Sprintf("  %s:%s", keyColor(sanitizedKey), strings.Repeat(" ", maxKeyLen-len(k)+1))
		fmt.Printf("%s%s\n", paddedKey, formatValue(header[k]))
	}
}
