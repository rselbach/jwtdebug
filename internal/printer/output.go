package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
)

// FormatData returns a string representation of data in the specified format.
// Supported formats are "pretty", "json", and "raw". An empty format is
// treated as "pretty".
func FormatData(data any, outputFormat string) (string, error) {
	switch outputFormat {
	case "pretty", "json", "":
		return formatJSON(data), nil
	case "raw":
		return formatRaw(data), nil
	default:
		return "", fmt.Errorf("unsupported format %q", outputFormat)
	}
}

// formatJSON formats the data as pretty-printed JSON with sanitized strings
func formatJSON(v any) string {
	sanitized := sanitizeValue(v)
	data, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %v", err)
	}
	return string(data)
}

// sanitizeValue recursively sanitizes all string values in a data structure
func sanitizeValue(v any) any {
	switch val := v.(type) {
	case string:
		return sanitizeString(val)
	case map[string]any:
		result := make(map[string]any, len(val))
		for k, v := range val {
			result[sanitizeString(k)] = sanitizeValue(v)
		}
		return result
	case []any:
		result := make([]any, len(val))
		for i, item := range val {
			result[i] = sanitizeValue(item)
		}
		return result
	default:
		return v
	}
}

// formatRaw formats the data as a simple key-value listing
func formatRaw(v any) string {
	switch val := v.(type) {
	case map[string]any:
		var lines []string
		var keys []string
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("%s: %s", sanitizeString(k), formatRawValue(val[k])))
		}
		return strings.Join(lines, "\n")
	default:
		return formatRawValue(val)
	}
}

// formatRawValue formats a value for the raw format
func formatRawValue(v any) string {
	switch val := v.(type) {
	case map[string]any:
		return fmt.Sprintf("{object with %d keys}", len(val))
	case []any:
		if len(val) == 0 {
			return "[]"
		}
		var items []string
		for _, item := range val {
			items = append(items, formatNestedValue(item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	case string:
		return sanitizeString(val)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func printSection(title string, titleColor *color.Color, pretty func(), data any, outputFormat string) {
	fmt.Println(titleColor.Sprint(title))
	if outputFormat == "pretty" || outputFormat == "" {
		pretty()
		fmt.Println()
		return
	}
	formatted, err := FormatData(data, outputFormat)
	if err != nil {
		fmt.Fprintf(color.Error, "Warning: %v, using 'json' instead\n", err)
		formatted = formatJSON(data)
	}
	fmt.Println(formatted)
	fmt.Println()
}

// maxStringLength returns the maximum length of strings in the slice.
func maxStringLength(strs []string) int {
	maxLen := 0
	for _, s := range strs {
		if len(s) > maxLen {
			maxLen = len(s)
		}
	}
	return maxLen
}

// sortedKeys returns the keys of a map sorted alphabetically.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// printKeyValueLines prints colored, padded key-value pairs.
// Each pair is a [2]string{key, value}. The indent parameter controls
// leading whitespace. maxKeyLen is used to align the colons.
func printKeyValueLines(lines [][2]string, indent int, maxKeyLen int) {
	if len(lines) == 0 {
		return
	}
	keyColor := color.New(color.FgCyan).SprintFunc()
	spaces := strings.Repeat(" ", indent)
	for _, line := range lines {
		paddedKey := fmt.Sprintf("%s%s:%s", spaces, keyColor(line[0]), strings.Repeat(" ", maxKeyLen-len(line[0])+1))
		fmt.Printf("%s%s\n", paddedKey, line[1])
	}
}
