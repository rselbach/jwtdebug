package printer

import (
	"fmt"

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

	keys := sortedKeys(header)
	lines := make([][2]string, 0, len(keys))
	for _, k := range keys {
		lines = append(lines, [2]string{sanitizeString(k), formatValue(header[k])})
	}
	printKeyValueLines(lines, 2, maxStringLength(keys))
}
