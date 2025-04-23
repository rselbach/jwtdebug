package printer

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/fatih/color"
	
	"github.com/rselbach/jwtdebug/internal/cli"
)

// PrintSignature prints information about the token signature
func PrintSignature(sigPart string) {
	sigTitle := color.New(color.FgYellow, color.Bold).SprintFunc()
	fmt.Println(sigTitle("SIGNATURE:"))
	
	if cli.OutputFormat == "pretty" || cli.OutputFormat == "" {
		// print raw signature in pretty format with alignment
		keyColor := color.New(color.FgCyan).SprintFunc()
		
		// Calculate padding for alignment
		labelLength := 12 // "Decoded (hex)" is the longest label
		
		fmt.Printf("  %s:%s%s\n", keyColor("Raw"), strings.Repeat(" ", labelLength-3), sigPart)
		
		// decode and print base64 if requested
		if cli.DecodeBase64 {
			sigBytes, err := base64.RawURLEncoding.DecodeString(sigPart)
			if err != nil {
				errMsg := fmt.Sprintf("Error decoding: %v", err)
				fmt.Printf("  %s:%s%s\n", keyColor("Decoded"), strings.Repeat(" ", labelLength-7), errMsg)
			} else {
				hexStr := fmt.Sprintf("%x", sigBytes)
				fmt.Printf("  %s:%s%s\n", keyColor("Decoded (hex)"), strings.Repeat(" ", labelLength-12), hexStr)
			}
		}
	} else {
		// For other formats, just output the signature as a simple object
		sigData := map[string]interface{}{
			"raw": sigPart,
		}
		
		if cli.DecodeBase64 {
			sigBytes, err := base64.RawURLEncoding.DecodeString(sigPart)
			if err == nil {
				sigData["decoded"] = fmt.Sprintf("%x", sigBytes)
			}
		}
		
		fmt.Println(FormatData(sigData))
	}
	
	fmt.Println()
}
