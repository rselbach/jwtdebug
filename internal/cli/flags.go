package cli

import (
	"flag"
	"fmt"

	"github.com/fatih/color"
)

// Version information will be set at build time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Flags holds all CLI flag values
type Flags struct {
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
}

// Explicit tracks which flags were explicitly set by the user
type Explicit struct {
	Header           bool
	Claims           bool
	Signature        bool
	KeyFile          bool
	Format           bool
	Color            bool
	Expiration       bool
	DecodeBase64     bool
	IgnoreExpiration bool
}

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

// InitFlags initializes all command-line flags on the provided Flags struct
func InitFlags(f *Flags) {
	// Output selection flags
	flag.BoolVar(&f.WithHeader, "header", false, "show token header")
	flag.BoolVar(&f.WithHeader, "H", false, "show token header (shorthand)")

	flag.BoolVar(&f.WithClaims, "claims", true, "show token claims (payload)")
	flag.BoolVar(&f.WithClaims, "c", true, "show token claims (payload) (shorthand)")

	flag.BoolVar(&f.WithSignature, "signature", false, "show token signature")
	flag.BoolVar(&f.WithSignature, "s", false, "show token signature (shorthand)")

	flag.BoolVar(&f.ShowAll, "all", false, "show all token parts and info")
	flag.BoolVar(&f.ShowAll, "a", false, "show all token parts and info (shorthand)")

	// Verification flags
	flag.BoolVar(&f.VerifySignature, "verify", false, "verify token signature (requires --key-file)")
	flag.BoolVar(&f.VerifySignature, "V", false, "verify token signature (shorthand)")

	flag.StringVar(&f.KeyFile, "key-file", "", "key file for signature verification")
	flag.StringVar(&f.KeyFile, "k", "", "key file for signature verification (shorthand)")
	// Deprecated alias
	flag.StringVar(&f.KeyFile, "key", "", "key file (deprecated: use --key-file)")

	flag.BoolVar(&f.IgnoreExpiration, "ignore-expiration", false, "ignore token expiration when verifying")
	// Deprecated alias
	flag.BoolVar(&f.IgnoreExpiration, "ignore-exp", false, "ignore expiration (deprecated: use --ignore-expiration)")

	// Output format flags
	flag.StringVar(&f.OutputFormat, "output", "pretty", "output format: pretty, json, or raw")
	flag.StringVar(&f.OutputFormat, "o", "pretty", "output format (shorthand)")
	// Deprecated alias
	flag.StringVar(&f.OutputFormat, "format", "pretty", "output format (deprecated: use --output)")

	flag.BoolVar(&f.OutputColor, "color", true, "colorize output")
	flag.BoolVar(&f.NoColor, "no-color", false, "disable colored output")
	flag.BoolVar(&f.RawClaims, "raw-claims", false, "output only raw claims JSON (for piping)")

	// Expiration flags
	flag.BoolVar(&f.ShowExpiration, "expiration", false, "check token expiration status")
	flag.BoolVar(&f.ShowExpiration, "e", false, "check token expiration status (shorthand)")
	// Deprecated alias
	flag.BoolVar(&f.ShowExpiration, "expiry", false, "check expiration (deprecated: use --expiration)")

	flag.BoolVar(&f.DecodeBase64, "decode-signature", false, "decode signature from base64 to hex")
	// Deprecated alias
	flag.BoolVar(&f.DecodeBase64, "decode-sig", false, "decode signature (deprecated: use --decode-signature)")

	// Config flags
	flag.StringVar(&f.ConfigFile, "config", "", "path to config file")
	flag.BoolVar(&f.SaveConfig, "save-config", false, "save current settings to config file")

	// Info flags
	flag.BoolVar(&f.ShowVersion, "version", false, "show version information")
	flag.BoolVar(&f.ShowHelp, "help", false, "show help message")
	flag.BoolVar(&f.ShowHelp, "h", false, "show help message (shorthand)")

	// Verbosity flags
	flag.BoolVar(&f.Quiet, "quiet", false, "suppress informational notices")
	flag.BoolVar(&f.Quiet, "q", false, "suppress informational notices (shorthand)")
	flag.BoolVar(&f.Verbose, "verbose", false, "enable verbose output for debugging")
	flag.BoolVar(&f.Verbose, "v", false, "enable verbose output for debugging (shorthand)")

	// Shell completion
	flag.StringVar(&f.CompletionShell, "completion", "", "generate shell completion script (bash, zsh, fish)")

	// Input parsing
	flag.BoolVar(&f.Strict, "strict", false, "disable smart token extraction (expect exact JWT input)")

	flag.Usage = PrintUsage
}

type flagMeta struct {
	setExplicit    func(*Explicit)
	deprecatedRepl string
}

var flagRegistry = map[string]flagMeta{
	"header":            {func(ex *Explicit) { ex.Header = true }, ""},
	"H":                 {func(ex *Explicit) { ex.Header = true }, ""},
	"claims":            {func(ex *Explicit) { ex.Claims = true }, ""},
	"c":                 {func(ex *Explicit) { ex.Claims = true }, ""},
	"signature":         {func(ex *Explicit) { ex.Signature = true }, ""},
	"s":                 {func(ex *Explicit) { ex.Signature = true }, ""},
	"key-file":          {func(ex *Explicit) { ex.KeyFile = true }, ""},
	"k":                 {func(ex *Explicit) { ex.KeyFile = true }, ""},
	"key":               {func(ex *Explicit) { ex.KeyFile = true }, "--key-file"},
	"output":            {func(ex *Explicit) { ex.Format = true }, ""},
	"o":                 {func(ex *Explicit) { ex.Format = true }, ""},
	"format":            {func(ex *Explicit) { ex.Format = true }, "--output"},
	"color":             {func(ex *Explicit) { ex.Color = true }, ""},
	"expiration":        {func(ex *Explicit) { ex.Expiration = true }, ""},
	"e":                 {func(ex *Explicit) { ex.Expiration = true }, ""},
	"expiry":            {func(ex *Explicit) { ex.Expiration = true }, "--expiration"},
	"decode-signature":  {func(ex *Explicit) { ex.DecodeBase64 = true }, ""},
	"decode-sig":        {func(ex *Explicit) { ex.DecodeBase64 = true }, "--decode-signature"},
	"ignore-expiration": {func(ex *Explicit) { ex.IgnoreExpiration = true }, ""},
	"ignore-exp":        {func(ex *Explicit) { ex.IgnoreExpiration = true }, "--ignore-expiration"},
}

// CheckExplicitFlags checks which flags were explicitly set by the user.
// Returns an error if the format flag was set to an invalid value.
func (f *Flags) CheckExplicitFlags(ex *Explicit) error {
	flag.Visit(func(fl *flag.Flag) {
		if meta, ok := flagRegistry[fl.Name]; ok {
			if meta.deprecatedRepl != "" {
				fmt.Fprintf(color.Error, "Warning: --%s is deprecated, use %s\n", fl.Name, meta.deprecatedRepl)
			}
			meta.setExplicit(ex)
		}
	})

	if ex.Format {
		if err := validateFormat(f.OutputFormat); err != nil {
			return err
		}
	}

	return nil
}

// PrintUsage prints the usage information
func PrintUsage() {
	fmt.Fprintf(color.Error, `JWT Debug Tool - Decode and analyze JWT tokens

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
func (f *Flags) ApplyAllFlag() {
	if f.ShowAll {
		f.WithHeader = true
		f.WithClaims = true
		f.WithSignature = true
		f.ShowExpiration = true
	}
}

// ApplyColorSettings syncs --no-color into OutputColor and the global color.NoColor
func (f *Flags) ApplyColorSettings() {
	if f.NoColor {
		f.OutputColor = false
	}
	color.NoColor = !f.OutputColor
}
