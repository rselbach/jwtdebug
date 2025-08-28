package printer

import (
	"fmt"
	"strings"
)

// sanitizeString removes ANSI escape initiators and control characters
// from a string, rendering control bytes as visible escape sequences.
// It preserves printable runes and replaces \n/\r/\t with escaped forms.
func sanitizeString(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			// Drop/encode ASCII control chars and DEL
			if (r >= 0 && r < 0x20) || r == 0x7f {
				b.WriteString(fmt.Sprintf("\\x%02X", r))
				continue
			}
			// ESC (0x1B) explicitly encoded
			if r == 0x1b {
				b.WriteString("\\x1B")
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
