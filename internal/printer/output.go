package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
)

// FormatData returns a string representation of data in the specified format
func FormatData(data any, outputFormat string) string {
	switch outputFormat {
	case "pretty", "json":
		return formatJSON(data)
	case "raw":
		return formatRaw(data)
	default:
		fmt.Fprintf(color.Error, "Warning: Unsupported format '%s', using 'json' instead\n", outputFormat)
		return formatJSON(data)
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
	fmt.Println(titleColor.SprintFunc()(title))
	if outputFormat == "pretty" || outputFormat == "" {
		pretty()
		fmt.Println()
		return
	}
	fmt.Println(FormatData(data, outputFormat))
	fmt.Println()
}
