package printer

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CheckExpiration checks and displays token expiration status.
func CheckExpiration(token *jwt.Token) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("EXPIRATION:")
		fmt.Println("Could not extract claims")
		return
	}

	now := time.Now().Unix()
	fmt.Println("EXPIRATION:")

	printTimeClaim("exp", claims, func(t time.Time) {
		expUnix := t.Unix()
		if now > expUnix {
			fmt.Printf("Token expired at %s (%d seconds ago)\n", t.Format(time.RFC3339), now-expUnix)
		} else {
			fmt.Printf("Token expires at %s (%d seconds from now)\n", t.Format(time.RFC3339), expUnix-now)
		}
	}, func() {
		fmt.Println("No expiration claim found")
	})

	printTimeClaim("nbf", claims, func(t time.Time) {
		nbfUnix := t.Unix()
		if now < nbfUnix {
			fmt.Printf("Token not valid yet. Valid from %s (in %d seconds)\n", t.Format(time.RFC3339), nbfUnix-now)
		} else {
			fmt.Printf("Token valid since %s (%d seconds ago)\n", t.Format(time.RFC3339), now-nbfUnix)
		}
	}, nil)

	printTimeClaim("iat", claims, func(t time.Time) {
		fmt.Printf("Issued at: %s (%d seconds ago)\n", t.Format(time.RFC3339), now-t.Unix())
	}, nil)

	fmt.Println()
}

func printTimeClaim(name string, claims jwt.MapClaims, onFound func(time.Time), onMissing func()) {
	if v, exists := claims[name]; exists {
		if t, ok := tryParseTimestamp(v); ok {
			onFound(t)
			return
		}
		fmt.Printf("Unrecognized %s value: %v\n", name, v)
		return
	}
	if onMissing != nil {
		onMissing()
	}
}

func tryParseTimestamp(v any) (time.Time, bool) {
	var timestamp int64

	switch val := v.(type) {
	case float64:
		if val > float64(1<<63-1) || val < float64(-1<<63) {
			return time.Time{}, false
		}
		timestamp = int64(val)
	case json.Number:
		ts, err := val.Int64()
		if err != nil {
			return time.Time{}, false
		}
		timestamp = ts
	case int64:
		timestamp = val
	case int:
		timestamp = int64(val)
	case string:
		t, err := time.Parse(time.RFC3339, val)
		if err == nil {
			return t, true
		}

		numVal, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		timestamp = numVal
	default:
		return time.Time{}, false
	}

	minTimestamp := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	maxTimestamp := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	if timestamp < minTimestamp || timestamp > maxTimestamp {
		return time.Time{}, false
	}

	return time.Unix(timestamp, 0), true
}
