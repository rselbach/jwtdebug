package printer

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rselbach/jwtdebug/internal/cli"
)

func TestFormatJSON(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// check if all keys are present
	for k, v := range testData {
		if val, ok := parsed[k]; !ok || !compareValues(v, val) {
			t.Errorf("Key %s: expected %v, got %v", k, v, val)
		}
	}
}

func TestFormatYAML(t *testing.T) {
	// test data
	testData := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	// format as YAML
	result := formatYAML(testData)

	// simple validation for YAML format
	if !strings.Contains(result, "key1: value1") || !strings.Contains(result, "key2: 42") {
		t.Errorf("YAML output doesn't contain expected values. Got: %s", result)
	}
}

func TestFormatRaw(t *testing.T) {
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
		if !strings.Contains(result, line) {
			t.Errorf("Raw output doesn't contain expected line '%s'. Got: %s", line, result)
		}
	}
}

func TestFormatData(t *testing.T) {
	// test data
	testData := map[string]interface{}{
		"key1": "value1",
		"key2": 42,
	}

	// test with JSON format
	cli.OutputFormat = "json"
	jsonResult := FormatData(testData)
	if !strings.Contains(jsonResult, "\"key1\": \"value1\"") {
		t.Errorf("JSON formatter not used correctly")
	}

	// test with YAML format
	cli.OutputFormat = "yaml"
	yamlResult := FormatData(testData)
	if !strings.Contains(yamlResult, "key1: value1") {
		t.Errorf("YAML formatter not used correctly")
	}

	// test with unsupported format (should default to JSON)
	cli.OutputFormat = "unsupported"
	defaultResult := FormatData(testData)
	if !strings.Contains(defaultResult, "\"key1\": \"value1\"") {
		t.Errorf("Default formatter (JSON) not used for unsupported format")
	}
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
