package printer

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTryParseTimestampEdgeCases(t *testing.T) {
	tests := map[string]struct {
		input  interface{}
		wantOK bool
	}{
		"empty string":            {input: "", wantOK: false},
		"non-numeric string":      {input: "hello world", wantOK: false},
		"random text":             {input: "not-a-timestamp", wantOK: false},
		"partial date string":     {input: "2024-13", wantOK: false},
		"invalid date format":     {input: "13/25/2024", wantOK: false},
		"float64 overflow max":    {input: float64(1 << 63), wantOK: false},
		"float64 overflow min":    {input: float64(-1 << 63), wantOK: false},
		"float64 positive inf":    {input: math.Inf(1), wantOK: false},
		"float64 negative inf":    {input: math.Inf(-1), wantOK: false},
		"timestamp before 2000":   {input: float64(946684799), wantOK: false},
		"timestamp after 2100":    {input: float64(4102444801), wantOK: false},
		"valid timestamp 2024":    {input: float64(1704067200), wantOK: true},
		"valid timestamp at min":  {input: float64(946684800), wantOK: true},
		"valid timestamp at max":  {input: float64(4102444800), wantOK: true},
		"json.Number valid":       {input: json.Number("1704067200"), wantOK: true},
		"json.Number invalid":     {input: json.Number("invalid"), wantOK: false},
		"json.Number overflow":    {input: json.Number("99999999999999999999"), wantOK: false},
		"int64 valid":             {input: int64(1704067200), wantOK: true},
		"int valid":               {input: int(1704067200), wantOK: true},
		"string numeric valid":    {input: "1704067200", wantOK: true},
		"string numeric invalid":  {input: "9999999999999999999999", wantOK: false},
		"RFC3339 string":          {input: "2024-01-01T00:00:00Z", wantOK: true},
		"ISO8601 with tz":         {input: "2024-01-01T00:00:00+00:00", wantOK: true},
		"date only":               {input: "2024-01-01", wantOK: true},
		"unsupported type bool":   {input: true, wantOK: false},
		"unsupported type slice":  {input: []int{1, 2, 3}, wantOK: false},
		"unsupported type nil":    {input: nil, wantOK: false},
		"unsupported type struct": {input: struct{}{}, wantOK: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			_, ok := tryParseTimestamp(tc.input)
			r.Equal(tc.wantOK, ok)
		})
	}
}

func TestFormatTimestamp(t *testing.T) {
	tests := map[string]struct {
		input  interface{}
		wantOK bool
	}{
		"valid unix timestamp":     {input: float64(1704067200), wantOK: true},
		"valid RFC3339":            {input: "2024-01-01T00:00:00Z", wantOK: true},
		"invalid string":           {input: "not-a-time", wantOK: false},
		"empty string":             {input: "", wantOK: false},
		"out of range timestamp":   {input: float64(100), wantOK: false},
		"bool type":                {input: false, wantOK: false},
		"nil":                      {input: nil, wantOK: false},
		"json.Number valid":        {input: json.Number("1704067200"), wantOK: true},
		"json.Number out of range": {input: json.Number("100"), wantOK: false},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			result, ok := formatTimestamp(tc.input)
			r.Equal(tc.wantOK, ok)
			if ok {
				r.NotEmpty(result)
			} else {
				r.Empty(result)
			}
		})
	}
}

func TestFormatValue(t *testing.T) {
	tests := map[string]struct {
		input interface{}
		want  string
	}{
		"nil returns null": {
			input: nil,
			want:  "null",
		},
		"empty array": {
			input: []interface{}{},
			want:  "[]",
		},
		"small array": {
			input: []interface{}{"a", "b", "c"},
			want:  "[a, b, c]",
		},
		"array at limit": {
			input: []interface{}{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			want:  "[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]",
		},
		"large array over limit": {
			input: []interface{}{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			want:  "[array with 11 items]",
		},
		"very large array": {
			input: make([]interface{}, 100),
			want:  "[array with 100 items]",
		},
		"empty object": {
			input: map[string]interface{}{},
			want:  "{}",
		},
		"nested object": {
			input: map[string]interface{}{"key": "value"},
			want:  "{object with 1 keys}",
		},
		"object with multiple keys": {
			input: map[string]interface{}{"a": 1, "b": 2, "c": 3},
			want:  "{object with 3 keys}",
		},
		"string value": {
			input: "hello",
			want:  "hello",
		},
		"string with special chars": {
			input: "hello\nworld",
			want:  "hello\\nworld",
		},
		"integer value": {
			input: 42,
			want:  "42",
		},
		"float value": {
			input: 3.14,
			want:  "3.14",
		},
		"boolean true": {
			input: true,
			want:  "true",
		},
		"boolean false": {
			input: false,
			want:  "false",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got := formatValue(tc.input)
			r.Equal(tc.want, got)
		})
	}
}

func TestFormatNestedValue(t *testing.T) {
	tests := map[string]struct {
		input interface{}
		want  string
	}{
		"string": {
			input: "hello",
			want:  "hello",
		},
		"string with newline": {
			input: "line1\nline2",
			want:  "line1\\nline2",
		},
		"empty array": {
			input: []interface{}{},
			want:  "[]",
		},
		"nested array": {
			input: []interface{}{[]interface{}{1, 2}, []interface{}{3, 4}},
			want:  "[[1, 2], [3, 4]]",
		},
		"deeply nested array": {
			input: []interface{}{[]interface{}{[]interface{}{1}}},
			want:  "[[[1]]]",
		},
		"empty object": {
			input: map[string]interface{}{},
			want:  "{}",
		},
		"simple object": {
			input: map[string]interface{}{"key": "value"},
			want:  "{key: value}",
		},
		"object with multiple keys sorted": {
			input: map[string]interface{}{"z": 1, "a": 2, "m": 3},
			want:  "{a: 2, m: 3, z: 1}",
		},
		"nested object": {
			input: map[string]interface{}{
				"outer": map[string]interface{}{
					"inner": "value",
				},
			},
			want: "{outer: {inner: value}}",
		},
		"mixed nested structure": {
			input: map[string]interface{}{
				"array": []interface{}{1, 2},
				"obj":   map[string]interface{}{"k": "v"},
			},
			want: "{array: [1, 2], obj: {k: v}}",
		},
		"integer": {
			input: 42,
			want:  "42",
		},
		"float": {
			input: 3.14159,
			want:  "3.14159",
		},
		"boolean": {
			input: true,
			want:  "true",
		},
		"nil in nested": {
			input: nil,
			want:  "<nil>",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got := formatNestedValue(tc.input)
			r.Equal(tc.want, got)
		})
	}
}
