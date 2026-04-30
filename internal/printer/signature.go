package printer

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// PrintSignature prints information about the token signature
func PrintSignature(sigPart, outputFormat string, decodeBase64 bool) {
	sigTitle := color.New(color.FgYellow, color.Bold)
	sigData := map[string]any{
		"raw": sigPart,
	}

	var decodedHex string
	var decodeErr error
	if decodeBase64 {
		sigBytes, err := base64.RawURLEncoding.DecodeString(sigPart)
		if err == nil {
			decodedHex = fmt.Sprintf("%x", sigBytes)
			sigData["decoded"] = decodedHex
		} else {
			decodeErr = err
		}
	}

	printSection("SIGNATURE:", sigTitle, func() {
		printPrettySignature(sigPart, decodeBase64, decodedHex, decodeErr)
	}, sigData, outputFormat)
}

func printPrettySignature(sigPart string, decodeBase64 bool, decodedHex string, decodeErr error) {
	keyColor := color.New(color.FgCyan).SprintFunc()
	labelLength := 12

	fmt.Printf("  %s:%s%s\n", keyColor("Raw"), strings.Repeat(" ", labelLength-3), sigPart)

	if decodeBase64 {
		if decodeErr != nil {
			errMsg := fmt.Sprintf("Error decoding: %v", decodeErr)
			fmt.Printf("  %s:%s%s\n", keyColor("Decoded"), strings.Repeat(" ", labelLength-7), errMsg)
			return
		}
		fmt.Printf("  %s:%s%s\n", keyColor("Decoded (hex)"), strings.Repeat(" ", labelLength-12), decodedHex)
	}
}
