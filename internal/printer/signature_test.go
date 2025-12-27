package printer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rselbach/jwtdebug/internal/cli"
)

func TestPrintSignature(t *testing.T) {
	tests := map[string]struct {
		sigPart      string
		outputFormat string
		decodeBase64 bool
	}{
		"pretty format without decode": {
			sigPart:      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			outputFormat: "pretty",
			decodeBase64: false,
		},
		"pretty format with decode": {
			sigPart:      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			outputFormat: "pretty",
			decodeBase64: true,
		},
		"json format without decode": {
			sigPart:      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			outputFormat: "json",
			decodeBase64: false,
		},
		"json format with decode": {
			sigPart:      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			outputFormat: "json",
			decodeBase64: true,
		},
		"raw format without decode": {
			sigPart:      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			outputFormat: "raw",
			decodeBase64: false,
		},
		"raw format with decode": {
			sigPart:      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			outputFormat: "raw",
			decodeBase64: true,
		},
		"empty signature pretty": {
			sigPart:      "",
			outputFormat: "pretty",
			decodeBase64: false,
		},
		"empty signature json": {
			sigPart:      "",
			outputFormat: "json",
			decodeBase64: false,
		},
		"short signature": {
			sigPart:      "abc",
			outputFormat: "pretty",
			decodeBase64: true,
		},
		"long RS256 signature": {
			sigPart:      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk-NhbqmEXZnvpfVQ3yNqXvHg-pVg2j-Dqk3_EYdkBJZw",
			outputFormat: "pretty",
			decodeBase64: true,
		},
		"default format (empty string)": {
			sigPart:      "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			outputFormat: "",
			decodeBase64: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			cli.OutputFormat = tc.outputFormat
			cli.DecodeBase64 = tc.decodeBase64

			r.NotPanics(func() {
				PrintSignature(tc.sigPart)
			})
		})
	}
}

func TestPrintSignatureInvalidBase64(t *testing.T) {
	tests := map[string]struct {
		sigPart      string
		outputFormat string
	}{
		"invalid base64 pretty": {
			sigPart:      "!!!invalid-base64!!!",
			outputFormat: "pretty",
		},
		"invalid base64 json": {
			sigPart:      "!!!invalid-base64!!!",
			outputFormat: "json",
		},
		"partially valid base64": {
			sigPart:      "abc===invalid",
			outputFormat: "pretty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			cli.OutputFormat = tc.outputFormat
			cli.DecodeBase64 = true

			r.NotPanics(func() {
				PrintSignature(tc.sigPart)
			})
		})
	}
}

func TestPrintSignatureFormats(t *testing.T) {
	tests := map[string]struct {
		outputFormat string
		decodeBase64 bool
	}{
		"pretty no decode": {
			outputFormat: "pretty",
			decodeBase64: false,
		},
		"pretty with decode": {
			outputFormat: "pretty",
			decodeBase64: true,
		},
		"json no decode": {
			outputFormat: "json",
			decodeBase64: false,
		},
		"json with decode": {
			outputFormat: "json",
			decodeBase64: true,
		},
		"raw no decode": {
			outputFormat: "raw",
			decodeBase64: false,
		},
		"raw with decode": {
			outputFormat: "raw",
			decodeBase64: true,
		},
	}

	validSignature := "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)

			cli.OutputFormat = tc.outputFormat
			cli.DecodeBase64 = tc.decodeBase64

			r.NotPanics(func() {
				PrintSignature(validSignature)
			})
		})
	}
}
