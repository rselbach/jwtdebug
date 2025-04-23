package printer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

// formatValue returns a nicely formatted string representation of a value
func formatValue(v interface{}) string {
	switch val := v.(type) {
	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		if len(val) > 10 {
			return fmt.Sprintf("[array with %d items]", len(val))
		}
		var items []string
		for _, item := range val {
			items = append(items, fmt.Sprintf("%v", item))
		}
		return "[" + strings.Join(items, ", ") + "]"
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		return fmt.Sprintf("{object with %d keys}", len(val))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// tryParseTimestamp attempts to parse various timestamp formats and returns
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

// formatTimestamp formats a value as a timestamp if possible
// Returns the formatted string and whether it was detected as a timestamp
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
