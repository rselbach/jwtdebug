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

	if decodeBase64 {
		sigBytes, err := base64.RawURLEncoding.DecodeString(sigPart)
		if err == nil {
			sigData["decoded"] = fmt.Sprintf("%x", sigBytes)
		}
	}

	printSection("SIGNATURE:", sigTitle, func() {
		printPrettySignature(sigPart, decodeBase64)
	}, sigData, outputFormat)
}

func printPrettySignature(sigPart string, decodeBase64 bool) {
	keyColor := color.New(color.FgCyan).SprintFunc()
	labelLength := 12

	fmt.Printf("  %s:%s%s\n", keyColor("Raw"), strings.Repeat(" ", labelLength-3), sigPart)

	if decodeBase64 {
		sigBytes, err := base64.RawURLEncoding.DecodeString(sigPart)
		if err != nil {
			errMsg := fmt.Sprintf("Error decoding: %v", err)
			fmt.Printf("  %s:%s%s\n", keyColor("Decoded"), strings.Repeat(" ", labelLength-7), errMsg)
			return
		}
		hexStr := fmt.Sprintf("%x", sigBytes)
		fmt.Printf("  %s:%s%s\n", keyColor("Decoded (hex)"), strings.Repeat(" ", labelLength-12), hexStr)
	}
}
