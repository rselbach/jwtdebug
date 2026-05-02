package printer

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatJSON(t *testing.T) {
	r := require.New(t)

	testData := map[string]any{
		"key1": "value1",
		"key2": 42,
		"key3": []any{"a", "b", "c"},
	}

	result := formatJSON(testData)

	var parsed map[string]any
	err := json.Unmarshal([]byte(result), &parsed)
	r.NoError(err, "Failed to parse JSON")

	for k, v := range testData {
		val, ok := parsed[k]
		r.True(ok, "Key %s not found", k)
		r.True(compareValues(v, val), "Key %s: expected %v, got %v", k, v, val)
	}
}

func TestFormatRaw(t *testing.T) {
	r := require.New(t)

	testData := map[string]any{
		"key1": "value1",
		"key2": 42,
	}

	result := formatRaw(testData)

	expectedLines := []string{
		"key1: value1",
		"key2: 42",
	}

	for _, line := range expectedLines {
		r.Contains(result, line, "Raw output doesn't contain expected line")
	}
}

func TestFormatData(t *testing.T) {
	r := require.New(t)

	testData := map[string]any{
		"key1": "value1",
		"key2": 42,
	}

	jsonResult, err := FormatData(testData, "json")
	r.NoError(err)
	r.Contains(jsonResult, "\"key1\": \"value1\"", "JSON formatter not used correctly")

	_, err = FormatData(testData, "unsupported")
	r.Error(err, "Expected error for unsupported format")
	r.Contains(err.Error(), "unsupported format")
}

func compareValues(expected, actual any) bool {
	switch e := expected.(type) {
	case []any:
		a, ok := actual.([]any)
		if !ok || len(e) != len(a) {
			return false
		}
		for i, v := range e {
			if !compareValues(v, a[i]) {
				return false
			}
		}
		return true
	case int:
		if f, ok := actual.(float64); ok {
			return float64(e) == f
		}
		return expected == actual
	case float64:
		if i, ok := actual.(int); ok {
			return e == float64(i)
		}
		return expected == actual
	default:
		return expected == actual
	}
}
