package jwtdebug

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var jwtPattern = regexp.MustCompile(`[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

var base64URL = base64.RawURLEncoding.Strict()

type parsedToken struct {
	raw       string
	header    map[string]any
	claims    map[string]any
	signature string
}

func parseToken(token string) (parsedToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return parsedToken{}, fmt.Errorf(
			"invalid token format: expected 3 parts separated by '.', got %d (token: %s)",
			len(parts),
			tokenSnippet(token),
		)
	}

	header, err := decodeJSONObject(parts[0])
	if err != nil {
		if errors.Is(err, errJSONNotObject) {
			return parsedToken{}, errors.New("token header is not a JSON object")
		}
		return parsedToken{}, fmt.Errorf("failed to parse token (%s): %w", tokenSnippet(token), err)
	}
	claims, err := decodeJSONObject(parts[1])
	if err != nil {
		if errors.Is(err, errJSONNotObject) {
			return parsedToken{}, errors.New("token claims is not a JSON object")
		}
		return parsedToken{}, fmt.Errorf("failed to parse token (%s): %w", tokenSnippet(token), err)
	}
	if _, err := decodeBase64URL(parts[2]); err != nil {
		return parsedToken{}, fmt.Errorf(
			"failed to decode token signature (%s): %w",
			tokenSnippet(token),
			err,
		)
	}

	return parsedToken{
		raw:       token,
		header:    header,
		claims:    claims,
		signature: parts[2],
	}, nil
}

func resolveToken(input string, strict bool) (parsedToken, error) {
	input = strings.TrimSpace(input)
	parsed, exactErr := parseToken(input)
	if exactErr == nil {
		return parsed, nil
	}
	if strict {
		return parsedToken{}, exactErr
	}

	for offset := 0; offset < len(input); {
		match := jwtPattern.FindStringIndex(input[offset:])
		if match == nil {
			break
		}
		start, end := offset+match[0], offset+match[1]
		offset = end
		if !hasExtractionBoundaries(input, start, end) {
			continue
		}
		candidate, err := parseToken(input[start:end])
		if err == nil {
			return candidate, nil
		}
	}

	return parsedToken{}, exactErr
}

func hasExtractionBoundaries(input string, start, end int) bool {
	if start > 0 {
		before, _ := utf8.DecodeLastRuneInString(input[:start])
		if !isExtractionBoundary(before) {
			return false
		}
	}
	if end < len(input) {
		after, _ := utf8.DecodeRuneInString(input[end:])
		if !isExtractionBoundary(after) {
			return false
		}
	}
	return true
}

func isExtractionBoundary(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	return strings.ContainsRune(`='"()[]{}<>,;:`, r)
}

func decodeJSONObject(segment string) (map[string]any, error) {
	data, err := decodeBase64URL(segment)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, errors.New("JSON segment is not valid UTF-8")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errMultipleJSONValues
		}
		return nil, err
	}

	object, ok := value.(map[string]any)
	if !ok {
		return nil, errJSONNotObject
	}
	return object, nil
}

func decodeBase64URL(segment string) ([]byte, error) {
	for index := range len(segment) {
		character := segment[index]
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return nil, fmt.Errorf("invalid base64url character at byte %d", index)
	}
	return base64URL.DecodeString(segment)
}

var (
	errMultipleJSONValues = errors.New("multiple JSON values")
	errJSONNotObject      = errors.New("JSON value is not an object")
)

func tokenSnippet(token string) string {
	if len(token) <= 20 {
		return token
	}

	runes := []rune(token)
	if len(runes) > 17 {
		runes = runes[:17]
	}
	return string(runes) + "..."
}

func prettyJSON(value any) (string, error) {
	return encodeJSON(value, true)
}

func compactJSON(value any) (string, error) {
	return encodeJSON(value, false)
}

func encodeJSON(value any, pretty bool) (string, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if pretty {
		encoder.SetIndent("", "  ")
	}
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buffer.String(), "\n"), nil
}
