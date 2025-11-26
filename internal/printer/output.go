package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/rselbach/jwtdebug/internal/cli"
)

// FormatMap maps the output format to the corresponding formatter function
var FormatMap = map[string]func(interface{}) string{
	"pretty": formatJSON, // "pretty" uses JSON for non-claims data
	"json":   formatJSON,
	"raw":    formatRaw,
}

// formatJSON formats the data as pretty-printed JSON with sanitized strings
func formatJSON(v interface{}) string {
	sanitized := sanitizeValue(v)
	data, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %v", err)
	}
	return string(data)
}

// sanitizeValue recursively sanitizes all string values in a data structure
func sanitizeValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return sanitizeString(val)
	case map[string]interface{}:
		result := make(map[string]interface{}, len(val))
		for k, v := range val {
			result[sanitizeString(k)] = sanitizeValue(v)
		}
		return result
	case []interface{}:
		result := make([]interface{}, len(val))
		for i, item := range val {
			result[i] = sanitizeValue(item)
		}
		return result
	default:
		return v
	}
}

// formatRaw formats the data as a simple key-value listing
func formatRaw(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		var lines []string
		// sort keys for consistent output
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
func formatRawValue(v interface{}) string {
	switch val := v.(type) {
	case map[string]interface{}:
		return fmt.Sprintf("{object with %d keys}", len(val))
	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		var items []string
		for _, item := range val {
			items = append(items, formatNestedValue(item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	default:
		if s, ok := v.(string); ok {
			return sanitizeString(s)
		}
		return fmt.Sprintf("%v", v)
	}
}

// FormatData returns a string representation of data in the specified format
func FormatData(data interface{}) string {
	formatter, ok := FormatMap[cli.OutputFormat]
	if !ok {
		// default to JSON if format is not supported (write warning to stderr)
		fmt.Fprintf(color.Error, "Warning: Unsupported format '%s', using 'json' instead\n", cli.OutputFormat)
		return formatJSON(data)
	}
	return formatter(data)
}

// PrintData prints the data to stdout in the specified format
func PrintData(data interface{}) {
	fmt.Println(FormatData(data))
}
