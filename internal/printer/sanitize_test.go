package printer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeString(t *testing.T) {
	cases := map[string]struct {
		in  string
		out string
	}{
		"plain text unchanged":    {"plain", "plain"},
		"escapes newline":         {"line1\nline2", "line1\\nline2"},
		"escapes tab":             {"a\tb", "a\\tb"},
		"escapes carriage return": {"a\rb", "a\\rb"},
		"escapes ANSI codes":      {"\x1b[31mred\x1b[0m", "\\x1B[31mred\\x1B[0m"},
		"escapes bell character":  {"bell:\a", "bell:\\x07"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got := sanitizeString(tc.in)
			r.Equal(tc.out, got, "sanitizeString(%q)", tc.in)
		})
	}
}
