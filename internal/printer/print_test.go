package printer

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestPrintHeader(t *testing.T) {
	token := &jwt.Token{
		Header: map[string]any{"alg": "HS256", "typ": "JWT"},
	}
	PrintHeader(token)
}

func TestPrintClaims(t *testing.T) {
	token := &jwt.Token{
		Claims: jwt.MapClaims{"sub": "user123"},
	}
	PrintClaims(token)
}

func TestPrintSignature(t *testing.T) {
	PrintSignature("sigPart")
}

func TestPrintVerificationMessages(t *testing.T) {
	PrintVerificationSuccess()
	PrintVerificationFailure(nil)
}
