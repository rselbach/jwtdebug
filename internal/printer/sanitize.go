package printer

import (
	"fmt"
	"strings"
)

// controlCharEscapes is a pre-computed lookup table for ASCII control characters (0x00-0x1F, 0x7F).
var controlCharEscapes [128]string

func init() {
	for i := 0; i < 0x20; i++ {
		controlCharEscapes[i] = fmt.Sprintf("\\x%02X", i)
	}
	controlCharEscapes[0x1b] = "\\x1B"
	controlCharEscapes[0x7f] = "\\x7F"
}

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
	b.Grow(len(s) * 2)
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString("\\n")
		case '\r':
			b.WriteString("\\r")
		case '\t':
			b.WriteString("\\t")
		default:
			if r < 0x20 || r == 0x7f {
				if r < 0x80 {
					b.WriteString(controlCharEscapes[r])
				} else {
					fmt.Fprintf(&b, "\\u%04X", r)
				}
				continue
			}
			// Unicode C1 control characters (0x80-0x9F)
			if r >= 0x80 && r <= 0x9F {
				fmt.Fprintf(&b, "\\u%04X", r)
				continue
			}
			// zero-width chars, bidi overrides, and BOM
			if (r >= 0x200B && r <= 0x200F) ||
				(r >= 0x202A && r <= 0x202E) ||
				(r >= 0x2066 && r <= 0x2069) ||
				r == 0xFEFF {
				fmt.Fprintf(&b, "\\u%04X", r)
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}
