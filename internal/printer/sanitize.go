package printer

import (
	"fmt"
	"strings"
)

// sanitizeString removes ANSI escape initiators and control characters
// from a string, rendering control bytes as visible escape sequences.
// It preserves printable runes and replaces \n/\r/\t with escaped forms.
//
// Security: This function also escapes Unicode bidirectional override characters
// (U+202A-U+202E, U+2066-U+2069), zero-width characters (U+200B-U+200F), and BOM
// (U+FEFF). These invisible characters can be exploited in "Trojan Source" attacks
// to make malicious code appear benign or to manipulate text rendering in security
// contexts like displaying JWT claims.
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
			// Unicode C1 control characters (0x80-0x9F)
			if r >= 0x80 && r <= 0x9F {
				b.WriteString(fmt.Sprintf("\\u%04X", r))
				continue
			}
			// zero-width chars, bidi overrides, and BOM that could be used for display attacks
			if (r >= 0x200B && r <= 0x200F) || // zero-width chars
				(r >= 0x202A && r <= 0x202E) || // bidi overrides
				(r >= 0x2066 && r <= 0x2069) || // bidi isolates
				r == 0xFEFF { // BOM/ZWNBSP
				b.WriteString(fmt.Sprintf("\\u%04X", r))
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
