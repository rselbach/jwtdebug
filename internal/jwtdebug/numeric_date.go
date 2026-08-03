package jwtdebug

import (
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

var (
	minimumNumericDate = big.NewInt(math.MinInt64)
	maximumNumericDate = new(big.Int).SetUint64(math.MaxUint64)
)

type numericDate struct {
	integer    *big.Int
	fractional float64
}

func parseNumericDate(value any) (numericDate, bool) {
	switch value := value.(type) {
	case json.Number:
		return parseJSONNumericDate(value.String())
	case string:
		if timestamp, err := time.Parse(time.RFC3339, value); err == nil {
			return integerNumericDate(big.NewInt(timestamp.Unix())), true
		}
		if timestamp, err := strconv.ParseInt(value, 10, 64); err == nil {
			return integerNumericDate(big.NewInt(timestamp)), true
		}
		return parseFractionalNumericDate(value)
	default:
		return numericDate{}, false
	}
}

func parseJSONNumericDate(value string) (numericDate, bool) {
	if !strings.ContainsAny(value, ".eE") {
		integer, ok := new(big.Int).SetString(value, 10)
		if !ok || integer.Cmp(minimumNumericDate) < 0 || integer.Cmp(maximumNumericDate) > 0 {
			return numericDate{}, false
		}
		return integerNumericDate(integer), true
	}
	return parseFractionalNumericDate(value)
}

func parseFractionalNumericDate(value string) (numericDate, bool) {
	timestamp, err := strconv.ParseFloat(value, 64)
	if err != nil || math.IsInf(timestamp, 0) || math.IsNaN(timestamp) {
		return numericDate{}, false
	}
	if timestamp < float64(math.MinInt64) || timestamp >= float64(math.MaxUint64) {
		return numericDate{}, false
	}
	return numericDate{fractional: timestamp}, true
}

func integerNumericDate(value *big.Int) numericDate {
	return numericDate{integer: value}
}

func (date numericDate) isBefore(timestamp time.Time) bool {
	if date.integer == nil {
		return date.fractional < unixSeconds(timestamp)
	}

	comparison := date.integer.Cmp(big.NewInt(timestamp.Unix()))
	return comparison < 0 || comparison == 0 && timestamp.Nanosecond() != 0
}

func (date numericDate) isAfter(timestamp time.Time) bool {
	if date.integer == nil {
		return date.fractional > unixSeconds(timestamp)
	}
	return date.integer.Cmp(big.NewInt(timestamp.Unix())) > 0
}

func (date numericDate) roundedSeconds() *big.Int {
	if date.integer != nil {
		return new(big.Int).Set(date.integer)
	}

	seconds, _ := big.NewFloat(math.Round(date.fractional)).Int(nil)
	return seconds
}

func unixSeconds(timestamp time.Time) float64 {
	return float64(timestamp.Unix()) + float64(timestamp.Nanosecond())/float64(time.Second)
}

type timeClaimKind uint8

const (
	timeClaimAbsent timeClaimKind = iota
	timeClaimInvalid
	timeClaimValid
)

type timeClaim struct {
	kind  timeClaimKind
	raw   any
	value numericDate
}

func classifyTimeClaim(claims map[string]any, name string) timeClaim {
	raw, ok := claims[name]
	if !ok {
		return timeClaim{kind: timeClaimAbsent}
	}
	value, ok := parseNumericDate(raw)
	if !ok {
		return timeClaim{kind: timeClaimInvalid, raw: raw}
	}
	return timeClaim{kind: timeClaimValid, value: value}
}
