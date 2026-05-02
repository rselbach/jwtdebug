package printer

import (
	"encoding/base64"
	"fmt"

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
	maxLen := len("Raw")
	lines := [][2]string{{"Raw", sigPart}}

	if decodeBase64 {
		maxLen = len("Decoded (hex)")
		if decodeErr != nil {
			lines = append(lines, [2]string{"Decoded", fmt.Sprintf("Error decoding: %v", decodeErr)})
		} else {
			lines = append(lines, [2]string{"Decoded (hex)", decodedHex})
		}
	}

	printKeyValueLines(lines, 2, maxLen)
}
