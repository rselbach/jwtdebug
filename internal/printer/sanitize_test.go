package printer

import "testing"

func TestSanitizeString(t *testing.T) {
	cases := []struct {
		in  string
		out string
	}{
		{"plain", "plain"},
		{"line1\nline2", "line1\\nline2"},
		{"a\tb", "a\\tb"},
		{"a\rb", "a\\rb"},
		{"\x1b[31mred\x1b[0m", "\\x1B[31mred\\x1B[0m"},
		{"bell:\a", "bell:\\x07"},
	}
	for _, c := range cases {
		got := sanitizeString(c.in)
		if got != c.out {
			t.Fatalf("sanitizeString(%q) => %q, want %q", c.in, got, c.out)
		}
	}
}
