package printer

import (
	"encoding/json"
	"testing"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/stretchr/testify/require"
)

func TestFormatJSON(t *testing.T) {
	r := require.New(t)

	// test data
	testData := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
		"key3": []interface{}{"a", "b", "c"},
	}

	// format as JSON
	result := formatJSON(testData)

	// parse back to ensure it's valid JSON
	var parsed map[string]interface{}
	err := json.Unmarshal([]byte(result), &parsed)
	r.NoError(err, "Failed to parse JSON")

	// check if all keys are present
	for k, v := range testData {
		val, ok := parsed[k]
		r.True(ok, "Key %s not found", k)
		r.True(compareValues(v, val), "Key %s: expected %v, got %v", k, v, val)
	}
}

func TestFormatRaw(t *testing.T) {
	r := require.New(t)

	// test data
	testData := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	// format as raw
	result := formatRaw(testData)

	// check if all keys are present in expected format
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

	// test data
	testData := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	// test with JSON format
	cli.OutputFormat = "json"
	jsonResult := FormatData(testData)
	r.Contains(jsonResult, "\"key1\": \"value1\"", "JSON formatter not used correctly")

	// test with unsupported format (should default to JSON)
	cli.OutputFormat = "unsupported"
	defaultResult := FormatData(testData)
	r.Contains(defaultResult, "\"key1\": \"value1\"", "Default formatter (JSON) not used for unsupported format")
}

// helper function to compare values
func compareValues(expected, actual interface{}) bool {
	switch e := expected.(type) {
	case []interface{}:
		a, ok := actual.([]interface{})
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
		// Handle JSON numbers (float64) comparison with integers
		if f, ok := actual.(float64); ok {
			return float64(e) == f
		}
		return expected == actual
	case float64:
		// Handle integer comparison with JSON float
		if i, ok := actual.(int); ok {
			return e == float64(i)
		}
		return expected == actual
	default:
		return expected == actual
	}
}
