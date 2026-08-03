package jwtdebug

import (
	"fmt"
	"math/big"
	"time"
)

func checkExpiration(claims map[string]any, now time.Time, out *output) {
	out.stdoutLine("EXPIRATION:")
	printExpirationClaim(classifyTimeClaim(claims, "exp"), now, out)
	printNotBeforeClaim(classifyTimeClaim(claims, "nbf"), now, out)
	printIssuedAtClaim(classifyTimeClaim(claims, "iat"), now, out)
	out.stdoutLine("")
}

func printExpirationClaim(claim timeClaim, now time.Time, out *output) {
	switch claim.kind {
	case timeClaimAbsent:
		out.stdoutLine("No expiration claim found")
	case timeClaimInvalid:
		out.stdoutLine("Unrecognized exp value: %s", formatJSONValue(claim.raw))
	case timeClaimValid:
		at, distance, future := resolveTime(claim.value, now)
		if future {
			out.stdoutLine("Token expires at %s (%s seconds from now)", at, distance)
			return
		}
		out.stdoutLine("Token expired at %s (%s seconds ago)", at, distance)
	}
}

func printNotBeforeClaim(claim timeClaim, now time.Time, out *output) {
	switch claim.kind {
	case timeClaimAbsent:
		return
	case timeClaimInvalid:
		out.stdoutLine("Unrecognized nbf value: %s", formatJSONValue(claim.raw))
	case timeClaimValid:
		at, distance, future := resolveTime(claim.value, now)
		if future {
			out.stdoutLine("Token not valid yet. Valid from %s (in %s seconds)", at, distance)
			return
		}
		out.stdoutLine("Token valid since %s (%s seconds ago)", at, distance)
	}
}

func printIssuedAtClaim(claim timeClaim, now time.Time, out *output) {
	switch claim.kind {
	case timeClaimAbsent:
		return
	case timeClaimInvalid:
		out.stdoutLine("Unrecognized iat value: %s", formatJSONValue(claim.raw))
	case timeClaimValid:
		at, distance, future := resolveTime(claim.value, now)
		if future {
			out.stdoutLine("Issued at: %s (%s seconds from now)", at, distance)
			return
		}
		out.stdoutLine("Issued at: %s (%s seconds ago)", at, distance)
	}
}

func resolveTime(date numericDate, now time.Time) (at string, distance *big.Int, future bool) {
	seconds := date.roundedSeconds()
	nowSeconds := big.NewInt(now.Unix())
	future = date.isAfter(now)
	if future {
		distance = new(big.Int).Sub(seconds, nowSeconds)
	} else {
		distance = new(big.Int).Sub(nowSeconds, seconds)
	}
	if distance.Sign() < 0 {
		distance.SetInt64(0)
	}
	return formatTimestamp(seconds), distance, future
}

func formatTimestamp(seconds *big.Int) string {
	if !seconds.IsInt64() {
		return seconds.String()
	}

	timestamp := time.Unix(seconds.Int64(), 0).UTC()
	if timestamp.Year() < 0 || timestamp.Year() > 9999 {
		return seconds.String()
	}
	return timestamp.Format(time.RFC3339)
}

func formatJSONValue(value any) string {
	formatted, err := compactJSON(value)
	if err == nil {
		return formatted
	}
	return fmt.Sprint(value)
}
