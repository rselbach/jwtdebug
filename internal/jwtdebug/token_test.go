package jwtdebug

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParseToken(t *testing.T) {
	tests := map[string]struct {
		token   string
		wantSub string
		wantErr string
	}{
		"valid": {
			token:   encodedToken(`{"alg":"HS256","typ":"JWT"}`, `{"sub":"Troy Barnes"}`, "signature"),
			wantSub: "Troy Barnes",
		},
		"large number remains exact": {
			token:   encodedToken(`{"alg":"none"}`, `{"sub":"9007199254740993","id":9007199254740993}`, ""),
			wantSub: "9007199254740993",
		},
		"wrong part count": {
			token:   "invalid.token",
			wantErr: "invalid token format",
		},
		"invalid signature encoding": {
			token:   encodedSegment(`{"alg":"HS256"}`) + "." + encodedSegment(`{"sub":"Annie Edison"}`) + ".@@@",
			wantErr: "failed to decode token signature",
		},
		"header must be object": {
			token:   encodedToken(`[1,2,3]`, `{"sub":"Abed Nadir"}`, ""),
			wantErr: "token header is not a JSON object",
		},
		"claims must be object": {
			token:   encodedToken(`{"alg":"none"}`, `[1,2,3]`, ""),
			wantErr: "token claims is not a JSON object",
		},
		"JSON must be UTF-8": {
			token:   base64.RawURLEncoding.EncodeToString([]byte{'{', '"', 0xff, '"', ':', '1', '}'}) + ".e30.",
			wantErr: "JSON segment is not valid UTF-8",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := parseToken(tc.token)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse token: %v", err)
			}
			if got := fmt.Sprint(parsed.claims["sub"]); got != tc.wantSub {
				t.Fatalf("sub = %q, want %q", got, tc.wantSub)
			}
		})
	}
}

func TestResolveToken(t *testing.T) {
	token := encodedToken(`{"alg":"none","typ":"JWT"}`, `{"sub":"Troy Barnes"}`, "")

	tests := map[string]struct {
		input   string
		strict  bool
		wantErr bool
	}{
		"exact":                  {input: token},
		"trims exact":            {input: "  " + token + "  ", strict: true},
		"bearer":                 {input: "Bearer " + token},
		"cookie":                 {input: "session=" + token + "; HttpOnly"},
		"JSON":                   {input: `{"access_token":"` + token + `"}`},
		"strict rejects bearer":  {input: "Bearer " + token, strict: true, wantErr: true},
		"embedded word rejected": {input: "prefix" + token + "suffix", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := resolveToken(tc.input, tc.strict)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected extraction to fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve token: %v", err)
			}
			if parsed.raw != token {
				t.Fatalf("raw token = %q, want %q", parsed.raw, token)
			}
		})
	}
}

func TestTokenSnippetHandlesMultibyteText(t *testing.T) {
	input := "这是没有JWT的中文文本测试一下看看会不会崩溃啊啊啊"
	if snippet := tokenSnippet(input); !strings.HasSuffix(snippet, "...") {
		t.Fatalf("snippet = %q", snippet)
	}
}

func encodedToken(header, claims, signature string) string {
	return encodedSegment(header) + "." + encodedSegment(claims) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(signature))
}

func encodedSegment(value string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(value))
}
