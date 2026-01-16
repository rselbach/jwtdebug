package cli

import (
	"flag"
	"fmt"
	"os"
)

// Version information will be set at build time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var (
	// Exported flag variables
	WithHeader       bool
	WithClaims       bool
	WithSignature    bool
	VerifySignature  bool
	KeyFile          string
	OutputFormat     string
	OutputColor      bool
	NoColor          bool
	ShowExpiration   bool
	ShowAll          bool
	DecodeBase64     bool
	IgnoreExpiration bool
	ConfigFile       string
	SaveConfig       bool
	ShowVersion      bool
	Quiet            bool
	Verbose          bool
	RawClaims        bool
	ShowHelp         bool
	CompletionShell  string
	Strict           bool

	// Track if flags were explicitly set by user
	HeaderExplicit           bool
	ClaimsExplicit           bool
	SignatureExplicit        bool
	KeyFileExplicit          bool
	FormatExplicit           bool
	ColorExplicit            bool
	ExpirationExplicit       bool
	DecodeBase64Explicit     bool
	IgnoreExpirationExplicit bool
)

// ValidFormats defines the allowed output formats
var ValidFormats = map[string]bool{
	"pretty": true,
	"json":   true,
	"raw":    true,
}

// validateFormat checks if the format is valid
func validateFormat(format string) error {
	if !ValidFormats[format] {
		return fmt.Errorf("invalid format %q, must be one of: pretty, json, raw", format)
	}
	return nil
}

// InitFlags initializes all command-line flags
func InitFlags() {
	// Output selection flags
	flag.BoolVar(&WithHeader, "header", false, "show token header")
	flag.BoolVar(&WithHeader, "H", false, "show token header (shorthand)")

	flag.BoolVar(&WithClaims, "claims", true, "show token claims (payload)")
	flag.BoolVar(&WithClaims, "c", true, "show token claims (payload) (shorthand)")

	flag.BoolVar(&WithSignature, "signature", false, "show token signature")
	flag.BoolVar(&WithSignature, "s", false, "show token signature (shorthand)")

	flag.BoolVar(&ShowAll, "all", false, "show all token parts and info")
	flag.BoolVar(&ShowAll, "a", false, "show all token parts and info (shorthand)")

	// Verification flags
	flag.BoolVar(&VerifySignature, "verify", false, "verify token signature (requires --key-file)")
	flag.BoolVar(&VerifySignature, "V", false, "verify token signature (shorthand)")

	flag.StringVar(&KeyFile, "key-file", "", "key file for signature verification")
	flag.StringVar(&KeyFile, "k", "", "key file for signature verification (shorthand)")
	// Deprecated alias
	flag.StringVar(&KeyFile, "key", "", "key file (deprecated: use --key-file)")

	flag.BoolVar(&IgnoreExpiration, "ignore-expiration", false, "ignore token expiration when verifying")
	// Deprecated alias
	flag.BoolVar(&IgnoreExpiration, "ignore-exp", false, "ignore expiration (deprecated: use --ignore-expiration)")

	// Output format flags
	flag.StringVar(&OutputFormat, "output", "pretty", "output format: pretty, json, or raw")
	flag.StringVar(&OutputFormat, "o", "pretty", "output format (shorthand)")
	// Deprecated alias
	flag.StringVar(&OutputFormat, "format", "pretty", "output format (deprecated: use --output)")

	flag.BoolVar(&OutputColor, "color", true, "colorize output")
	flag.BoolVar(&NoColor, "no-color", false, "disable colored output")
	flag.BoolVar(&RawClaims, "raw-claims", false, "output only raw claims JSON (for piping)")

	// Expiration flags
	flag.BoolVar(&ShowExpiration, "expiration", false, "check token expiration status")
	flag.BoolVar(&ShowExpiration, "e", false, "check token expiration status (shorthand)")
	// Deprecated alias
	flag.BoolVar(&ShowExpiration, "expiry", false, "check expiration (deprecated: use --expiration)")

	flag.BoolVar(&DecodeBase64, "decode-signature", false, "decode signature from base64 to hex")
	// Deprecated alias
	flag.BoolVar(&DecodeBase64, "decode-sig", false, "decode signature (deprecated: use --decode-signature)")

	// Config flags
	flag.StringVar(&ConfigFile, "config", "", "path to config file")
	flag.BoolVar(&SaveConfig, "save-config", false, "save current settings to config file")

	// Info flags
	flag.BoolVar(&ShowVersion, "version", false, "show version information")
	flag.BoolVar(&ShowHelp, "help", false, "show help message")
	flag.BoolVar(&ShowHelp, "h", false, "show help message (shorthand)")

	// Verbosity flags
	flag.BoolVar(&Quiet, "quiet", false, "suppress informational notices")
	flag.BoolVar(&Quiet, "q", false, "suppress informational notices (shorthand)")
	flag.BoolVar(&Verbose, "verbose", false, "enable verbose output for debugging")
	flag.BoolVar(&Verbose, "v", false, "enable verbose output for debugging (shorthand)")

	// Shell completion
	flag.StringVar(&CompletionShell, "completion", "", "generate shell completion script (bash, zsh, fish)")

	// Input parsing
	flag.BoolVar(&Strict, "strict", false, "disable smart token extraction (expect exact JWT input)")

	flag.Usage = PrintUsage
}

// CheckExplicitFlags checks which flags were explicitly set by the user
func CheckExplicitFlags() {
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "header", "H":
			HeaderExplicit = true
		case "claims", "c":
			ClaimsExplicit = true
		case "signature", "s":
			SignatureExplicit = true
		case "key-file", "k", "key":
			KeyFileExplicit = true
		case "output", "o", "format":
			FormatExplicit = true
		case "color":
			ColorExplicit = true
		case "expiration", "e", "expiry":
			ExpirationExplicit = true
		case "decode-signature", "decode-sig":
			DecodeBase64Explicit = true
		case "ignore-expiration", "ignore-exp":
			IgnoreExpirationExplicit = true
		}
	})

	// Validate format if it was set
	if FormatExplicit {
		if err := validateFormat(OutputFormat); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

// PrintUsage prints the usage information
func PrintUsage() {
	fmt.Fprintf(os.Stderr, `JWT Debug Tool - Decode and analyze JWT tokens

Usage: jwtdebug [options] [token]
       jwtdebug [options] -           # read from stdin explicitly
       command | jwtdebug [options]   # read from pipe

If no token is provided, jwtdebug reads from stdin.

Options:
  Display:
    -a, --all                Show all token parts and info
    -H, --header             Show token header
    -c, --claims             Show token claims/payload (default: true)
    -s, --signature          Show token signature
    -e, --expiration         Check token expiration status
        --decode-signature   Decode signature from base64 to hex
        --raw-claims         Output only raw claims JSON (for piping to jq)

  Verification:
    -V, --verify             Verify token signature (requires --key-file)
    -k, --key-file <file>    Key file for signature verification
        --ignore-expiration  Ignore token expiration when verifying

  Output:
    -o, --output <format>    Output format: pretty, json, or raw (default: pretty)
        --color              Colorize output (default: true)
        --no-color           Disable colored output

  Configuration:
        --config <file>      Path to config file
        --save-config        Save current settings to config file

  Input:
        --strict             Disable smart extraction (expect exact JWT input)

  Other:
    -h, --help               Show this help message
        --version            Show version information
    -q, --quiet              Suppress informational notices
    -v, --verbose            Enable verbose output for debugging
        --completion <shell> Generate shell completion script (bash, zsh, fish)

Examples:
  jwtdebug eyJhbGci...              # Decode a token
  echo "Bearer eyJ..." | jwtdebug   # Read from pipe (strips "Bearer " prefix)
  pbpaste | jwtdebug                # Decode token from clipboard (macOS)
  jwtdebug -a token                 # Show all parts (header, claims, signature, expiry)
  jwtdebug -V -k pub.pem token      # Verify signature with public key
  jwtdebug -o json token            # Output as JSON
  jwtdebug --raw-claims token | jq  # Pipe claims to jq

Exit Codes:
  0  Success
  1  General error
  2  Invalid token format
  3  Signature verification failed
  4  Configuration error

For more information, see: https://github.com/rselbach/jwtdebug
`)
}

// ApplyAllFlag enables all output options if the -all flag is set
func ApplyAllFlag() {
	if ShowAll {
		WithHeader = true
		WithClaims = true
		WithSignature = true
		ShowExpiration = true
	}
}

// ApplyNoColor sets OutputColor to false if --no-color is specified
func ApplyNoColor() {
	if NoColor {
		OutputColor = false
	}
}
