package printer

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestTryParseTimestamp_StringEpoch(t *testing.T) {
	r := require.New(t)
	ts := "1700000000"
	got, ok := tryParseTimestamp(ts)
	r.True(ok, "expected ok=true for numeric string epoch")
	r.Equal(int64(1700000000), got.Unix())
}

func TestTryParseTimestamp_RFC3339(t *testing.T) {
	r := require.New(t)
	ts := "2006-01-02T15:04:05Z"
	got, ok := tryParseTimestamp(ts)
	r.True(ok, "expected ok=true for RFC3339")
	want := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	r.True(got.Equal(want), "unexpected time: got %v want %v", got, want)
}

func TestTryParseTimestamp_OutOfRange(t *testing.T) {
	r := require.New(t)
	got, ok := tryParseTimestamp(int64(100))
	r.False(ok, "expected ok=false for out-of-range timestamp, got %v", got)
}

func captureOutput(f func()) string {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	oldStdout := os.Stdout
	oldColorOutput := color.Output

	r, w, _ := os.Pipe()
	os.Stdout = w
	color.Output = w

	f()

	w.Close()
	os.Stdout = oldStdout
	color.Output = oldColorOutput

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestCheckExpiration(t *testing.T) {
	tests := map[string]struct {
		claims       jwt.MapClaims
		wantContains []string
	}{
		"expired token": {
			claims: jwt.MapClaims{
				"exp": time.Now().Add(-time.Hour).Unix(),
			},
			wantContains: []string{"Token expired at", "seconds ago"},
		},
		"valid token": {
			claims: jwt.MapClaims{
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			wantContains: []string{"Token expires at", "seconds from now"},
		},
		"missing exp claim": {
			claims:       jwt.MapClaims{},
			wantContains: []string{"No expiration claim found"},
		},
		"nbf in future": {
			claims: jwt.MapClaims{
				"nbf": time.Now().Add(time.Hour).Unix(),
			},
			wantContains: []string{"Token not valid yet"},
		},
		"nbf in past": {
			claims: jwt.MapClaims{
				"nbf": time.Now().Add(-time.Hour).Unix(),
			},
			wantContains: []string{"Token valid since"},
		},
		"unrecognized exp value": {
			claims: jwt.MapClaims{
				"exp": "not-a-timestamp",
			},
			wantContains: []string{"Unrecognized expiration value"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			token := &jwt.Token{
				Claims: tc.claims,
			}

			output := captureOutput(func() {
				CheckExpiration(token)
			})

			for _, want := range tc.wantContains {
				r.Contains(output, want)
			}
		})
	}
}
