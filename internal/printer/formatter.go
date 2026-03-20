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

func formatInlineArray(items []any, formatItem func(any) string) string {
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

func formatNestedValue(v any) string {
	switch val := v.(type) {
	case string:
		return sanitizeString(val)
	case []any:
		return formatInlineArray(val, formatNestedValue)
	case map[string]any:
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

func formatValue(v any) string {
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case []any:
		if len(val) > maxArrayItemsToDisplay {
			return fmt.Sprintf("[array with %d items]", len(val))
		}
		return formatInlineArray(val, formatNestedValue)
	case map[string]any:
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

func tryParseTimestamp(v any) (time.Time, bool) {
	var timestamp int64

	switch val := v.(type) {
	case float64:
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
		t, err := time.Parse(time.RFC3339, val)
		if err == nil {
			return t, true
		}

		for _, format := range timestampFormats {
			t, err := time.Parse(format, val)
			if err == nil {
				return t, true
			}
		}

		numVal, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		timestamp = numVal
	default:
		return time.Time{}, false
	}

	if timestamp < minTimestamp || timestamp > maxTimestamp {
		return time.Time{}, false
	}

	return time.Unix(timestamp, 0), true
}

func formatTimestamp(v any) (string, bool) {
	timeColor := color.New(color.FgYellow).SprintFunc()

	t, ok := tryParseTimestamp(v)
	if !ok {
		return "", false
	}

	return fmt.Sprintf("%v %s", v, timeColor(t.Format(time.RFC3339))), true
}
