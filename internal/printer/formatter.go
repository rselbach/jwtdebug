package printer

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/rselbach/jwtdebug/internal/cli"
)

const (
	// maxArrayItemsToDisplay is the maximum number of array items to display inline
	// before showing a summary instead
	maxArrayItemsToDisplay = 10
)

var (
	minTimestamp     = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	maxTimestamp     = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	timestampFormats = []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		time.RFC1123,
		time.RFC1123Z,
		time.RFC822,
		time.RFC822Z,
		time.RFC850,
	}
)

func formatInlineArray(items []interface{}, formatItem func(interface{}) string) string {
	if len(items) == 0 {
		return "[]"
	}
	var b strings.Builder
	b.WriteString("[")
	for i, item := range items {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(formatItem(item))
	}
	b.WriteString("]")
	return b.String()
}

// formats a value for display within nested structures like arrays and objects
func formatNestedValue(v interface{}) string {
	switch val := v.(type) {
	case string:
		return sanitizeString(val)
	case []interface{}:
		return formatInlineArray(val, formatNestedValue)
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
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case []interface{}:
		if len(val) > maxArrayItemsToDisplay {
			return fmt.Sprintf("[array with %d items]", len(val))
		}
		return formatInlineArray(val, formatNestedValue)
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		return fmt.Sprintf("{object with %d keys}", len(val))
	case string:
		return sanitizeString(val)
	default:
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
		// check for overflow before conversion
		if val > float64(1<<63-1) || val < float64(-1<<63) {
			return time.Time{}, false
		}
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
		for _, format := range timestampFormats {
			t, err := time.Parse(format, val)
			if err == nil {
				return t, true
			}
		}

		// If all string parsing failed, try to convert to a number
		// as it might be a numeric timestamp in string form
		numVal, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		timestamp = numVal
	default:
		return time.Time{}, false
	}

	// Check if the timestamp is in a reasonable range
	// (between 2000-01-01 and 2100-01-01)
	if timestamp < minTimestamp || timestamp > maxTimestamp {
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
	if cli.Quiet {
		return
	}
	notice := color.New(color.FgYellow).Sprintf("Note: claims are unverified. Use -verify -key to validate.")
	fmt.Fprintln(color.Error, notice)
}
