package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"gopkg.in/yaml.v3"

	"github.com/rselbach/jwtdebug/internal/cli"
)

// FormatMap maps the output format to the corresponding formatter function
var FormatMap = map[string]func(interface{}) string{
	"pretty": formatJSON, // "pretty" uses JSON for non-claims data
	"json":   formatJSON,
	"yaml":   formatYAML,
	"raw":    formatRaw,
}

// formatJSON formats the data as pretty-printed JSON
func formatJSON(v interface{}) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting JSON: %v", err)
	}
	return string(data)
}

// formatYAML formats the data as YAML
func formatYAML(v interface{}) string {
	data, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Sprintf("Error formatting YAML: %v", err)
	}
	return string(data)
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
			lines = append(lines, fmt.Sprintf("%s: %v", k, formatRawValue(val[k])))
		}
		return strings.Join(lines, "\n")
	default:
		return fmt.Sprintf("%v", v)
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
			items = append(items, fmt.Sprintf("%v", item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	default:
		return fmt.Sprintf("%v", v)
	}
}

// FormatData returns a string representation of data in the specified format
func FormatData(data interface{}) string {
	formatter, ok := FormatMap[cli.OutputFormat]
	if !ok {
		// default to JSON if format is not supported
		color.Yellow("Warning: Unsupported format '%s', using 'json' instead", cli.OutputFormat)
		return formatJSON(data)
	}
	return formatter(data)
}

// PrintData prints the data to stdout in the specified format
func PrintData(data interface{}) {
	fmt.Println(FormatData(data))
}
