package jwtdebug

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseNumericDate(t *testing.T) {
	tests := map[string]struct {
		input          any
		wantInteger    string
		wantFractional float64
		wantValid      bool
	}{
		"integer number": {
			input:       json.Number("1700000000"),
			wantInteger: "1700000000",
			wantValid:   true,
		},
		"maximum unsigned integer": {
			input:       json.Number("18446744073709551615"),
			wantInteger: "18446744073709551615",
			wantValid:   true,
		},
		"fractional number": {
			input:          json.Number("1700000000.5"),
			wantFractional: 1700000000.5,
			wantValid:      true,
		},
		"exponent number": {
			input:          json.Number("1e19"),
			wantFractional: 1e19,
			wantValid:      true,
		},
		"numeric string": {
			input:       "1700000000",
			wantInteger: "1700000000",
			wantValid:   true,
		},
		"fractional numeric string": {
			input:          "1700000000.5",
			wantFractional: 1700000000.5,
			wantValid:      true,
		},
		"RFC3339": {
			input:       "2006-01-02T15:04:05Z",
			wantInteger: "1136214245",
			wantValid:   true,
		},
		"negative epoch": {
			input:       json.Number("-1"),
			wantInteger: "-1",
			wantValid:   true,
		},
		"too large integer": {input: json.Number("18446744073709551616")},
		"too small integer": {input: json.Number("-9223372036854775809")},
		"infinity":          {input: "inf"},
		"not a date":        {input: "not-a-date"},
		"empty string":      {input: ""},
		"boolean":           {input: true},
		"null":              {input: nil},
		"array":             {input: []any{}},
		"object":            {input: map[string]any{}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := parseNumericDate(tc.input)
			if ok != tc.wantValid {
				t.Fatalf("valid = %t, want %t (value: %+v)", ok, tc.wantValid, got)
			}
			if !ok {
				return
			}
			if tc.wantInteger != "" {
				if got.integer == nil || got.integer.String() != tc.wantInteger {
					t.Fatalf("integer = %v, want %s", got.integer, tc.wantInteger)
				}
				return
			}
			if got.integer != nil || got.fractional != tc.wantFractional {
				t.Fatalf("date = %+v, want fractional %v", got, tc.wantFractional)
			}
		})
	}
}

func TestNumericDateComparesSubsecondTimes(t *testing.T) {
	now := time.Unix(1_700_000_000, 750_000_000)
	tests := map[string]struct {
		date       numericDate
		wantBefore bool
		wantAfter  bool
	}{
		"past fraction": {
			date:       numericDate{fractional: 1_700_000_000.5},
			wantBefore: true,
		},
		"future fraction": {
			date:      numericDate{fractional: 1_700_000_000.9},
			wantAfter: true,
		},
		"integer at current second": {
			date:       integerNumericDate(big.NewInt(1_700_000_000)),
			wantBefore: true,
		},
		"next integer second": {
			date:      integerNumericDate(big.NewInt(1_700_000_001)),
			wantAfter: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := tc.date.isBefore(now); got != tc.wantBefore {
				t.Fatalf("isBefore = %t, want %t", got, tc.wantBefore)
			}
			if got := tc.date.isAfter(now); got != tc.wantAfter {
				t.Fatalf("isAfter = %t, want %t", got, tc.wantAfter)
			}
		})
	}
}

func TestExpirationReport(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{
		"exp": json.Number("1699999900"),
		"nbf": json.Number("1699999800"),
		"iat": json.Number("1700000100"),
	}
	var stdout strings.Builder
	out := newOutput(&stdout, &strings.Builder{})

	checkExpiration(claims, now, out)

	got := stdout.String()
	for _, want := range []string{
		"Token expired at 2023-11-14T22:11:40Z (100 seconds ago)",
		"Token valid since 2023-11-14T22:10:00Z (200 seconds ago)",
		"Issued at: 2023-11-14T22:15:00Z (100 seconds from now)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

func TestFormatTimestampPreservesUnsupportedRange(t *testing.T) {
	for _, value := range []string{"18446744073709551615", "-9223372036854775808"} {
		seconds, ok := new(big.Int).SetString(value, 10)
		if !ok {
			t.Fatalf("parse test integer %q", value)
		}
		if got := formatTimestamp(seconds); got != value {
			t.Fatalf("formatTimestamp(%s) = %q", value, got)
		}
	}
}
