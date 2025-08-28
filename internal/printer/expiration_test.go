package printer

import (
	"testing"
	"time"
)

func TestTryParseTimestamp_StringEpoch(t *testing.T) {
	ts := "1700000000"
	got, ok := tryParseTimestamp(ts)
	if !ok {
		t.Fatalf("expected ok=true for numeric string epoch")
	}
	if got.Unix() != 1700000000 {
		t.Fatalf("unexpected unix: got %d", got.Unix())
	}
}

func TestTryParseTimestamp_RFC3339(t *testing.T) {
	ts := "2006-01-02T15:04:05Z"
	got, ok := tryParseTimestamp(ts)
	if !ok {
		t.Fatalf("expected ok=true for RFC3339")
	}
	want := time.Date(2006, 1, 2, 15, 4, 5, 0, time.UTC)
	if !got.Equal(want) {
		t.Fatalf("unexpected time: got %v want %v", got, want)
	}
}

func TestTryParseTimestamp_OutOfRange(t *testing.T) {
	// year 1970: should be out of allowed range (min 2000)
	got, ok := tryParseTimestamp(int64(100))
	if ok {
		t.Fatalf("expected ok=false for out-of-range timestamp, got %v", got)
	}
}
