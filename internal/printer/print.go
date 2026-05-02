package printer

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/color"
	"github.com/golang-jwt/jwt/v5"
)

// PrintHeader prints the token header as JSON.
func PrintHeader(token *jwt.Token) {
	fmt.Println("HEADER:")
	data, _ := json.MarshalIndent(token.Header, "", "  ")
	fmt.Println(string(data))
	fmt.Println()
}

// PrintClaims prints the token claims as JSON.
func PrintClaims(token *jwt.Token) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("CLAIMS:")
		fmt.Println("Could not extract claims")
		return
	}
	fmt.Println("CLAIMS:")
	data, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println(string(data))
	fmt.Println()
}

// PrintSignature prints the token signature as JSON.
func PrintSignature(sigPart string) {
	fmt.Println("SIGNATURE:")
	data, _ := json.MarshalIndent(map[string]string{"raw": sigPart}, "", "  ")
	fmt.Println(string(data))
	fmt.Println()
}

// PrintVerificationSuccess prints a success message for signature verification.
func PrintVerificationSuccess() {
	fmt.Println("Signature verified successfully")
}

// PrintVerificationFailure prints a failure message for signature verification.
func PrintVerificationFailure(err error) {
	fmt.Printf("Signature verification failed: %v\n", err)
}

// PrintUnverifiedNotice prints a single-line warning that claims are unverified.
func PrintUnverifiedNotice(quiet bool) {
	if quiet {
		return
	}
	fmt.Fprintln(color.Error, "Note: claims are unverified. Use --verify --key-file to validate.")
}
