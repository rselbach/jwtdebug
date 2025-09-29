package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

const (
	// maxArrayItemsToDisplay is the maximum number of array items to display inline
	// before showing a summary instead
	maxArrayItemsToDisplay = 10
)

// formats a value for display within nested structures like arrays and objects
func formatNestedValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return sanitizeString(val)
	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		var b strings.Builder
		b.WriteString("[")
		for i, item := range val {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(formatNestedValue(item))
		}
		b.WriteString("]")
		return b.String()
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var b strings.Builder
		b.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(sanitizeString(k))
			b.WriteString(": ")
			b.WriteString(formatNestedValue(val[k]))
		}
		b.WriteString("}")
		return b.String()
	default:
		return fmt.Sprintf("%v", val)
	}
}

// returns a nicely formatted string representation of a value
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		if len(val) > maxArrayItemsToDisplay {
			return fmt.Sprintf("[array with %d items]", len(val))
		}
		var b strings.Builder
		b.WriteString("[")
		for i, item := range val {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(formatNestedValue(item))
		}
		b.WriteString("]")
		return b.String()
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		return fmt.Sprintf("{object with %d keys}", len(val))
	default:
		if s, ok := v.(string); ok {
			return sanitizeString(s)
		}
		return fmt.Sprintf("%v", v)
	}
}

// attempts to parse various timestamp formats and returns
// the time and whether parsing was successful
func tryParseTimestamp(v interface{}) (time.Time, bool) {
	var timestamp int64

	// Try to convert to int64 from different numeric types
	switch val := v.(type) {
	case float64:
		timestamp = int64(val)
	case json.Number:
		ts, err := val.Int64()
		if err != nil {
			return time.Time{}, false
		}
		timestamp = ts
	case int64:
		timestamp = val
	case int:
		timestamp = int64(val)
	case string:
		// Try to parse string directly as a timestamp - if it fails, it's not a time
		// Try RFC3339 format first
		t, err := time.Parse(time.RFC3339, val)
		if err == nil {
			return t, true
		}

		// Try common variations
		formats := []string{
			"2006-01-02T15:04:05Z07:00", // ISO8601 with timezone
			"2006-01-02T15:04:05",       // ISO8601 without timezone
			"2006-01-02 15:04:05",       // Common datetime format
			"2006-01-02",                // Date only
			time.RFC1123,
			time.RFC1123Z,
			time.RFC822,
			time.RFC822Z,
			time.RFC850,
		}

		for _, format := range formats {
			t, err := time.Parse(format, val)
			if err == nil {
				return t, true
			}
		}

		// If all string parsing failed, try to convert to a number
		// as it might be a numeric timestamp in string form
		if numVal, err := strconv.ParseInt(val, 10, 64); err == nil {
			timestamp = numVal
		} else {
			return time.Time{}, false
		}
	default:
		return time.Time{}, false
	}

	// Check if the timestamp is in a reasonable range
	// (between 2000-01-01 and 2100-01-01)
	minTime := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	maxTime := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	if timestamp < minTime || timestamp > maxTime {
		return time.Time{}, false
	}

	return time.Unix(timestamp, 0), true
}

// formats a value as a timestamp if possible.
// returns the formatted string and whether it was detected as a timestamp
func formatTimestamp(v interface{}) (string, bool) {
	timeColor := color.New(color.FgYellow).SprintFunc()

	t, ok := tryParseTimestamp(v)
	if !ok {
		return "", false
	}

	// Format as both the original value and the time string
	return fmt.Sprintf("%v %s", v, timeColor(t.Format(time.RFC3339))), true
}

// PrintVerificationSuccess prints a success message for signature verification
func PrintVerificationSuccess() {
	color.Green("✓ Signature verified successfully")
}

// PrintVerificationFailure prints a failure message for signature verification
func PrintVerificationFailure(err error) {
	color.Red("✗ Signature verification failed: %v", err)
}

// PrintUnverifiedNotice prints a single-line warning that claims are unverified.
// Printed to stderr to avoid breaking machine-readable stdout formats.
func PrintUnverifiedNotice() {
	notice := color.New(color.FgYellow).Sprintf("Note: claims are unverified. Use -verify -key to validate.")
	fmt.Fprintln(color.Error, notice)
}
