package cli

import (
	"flag"
	"fmt"
	"os"
	"strconv"
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

// Custom flag types to track if flags were set
type boolFlag struct {
	set      *bool
	value    *bool
	defValue bool
}

func (f boolFlag) IsBoolFlag() bool { return true }
func (f boolFlag) String() string {
	if f.value == nil {
		return fmt.Sprintf("%v", f.defValue)
	}
	return fmt.Sprintf("%v", *f.value)
}
func (f boolFlag) Set(s string) error {
	if f.set != nil {
		*f.set = true
	}
	if f.value != nil {
		// Accept standard boolean forms (true/false, 1/0, t/f, yes/no)
		// Return an error on invalid values so flag.Parse can surface it
		parsed, err := strconv.ParseBool(s)
		if err != nil {
			return err
		}
		*f.value = parsed
	}
	return nil
}

type stringFlag struct {
	set       *bool
	value     *string
	defValue  string
	validator func(string) error
}

func (f stringFlag) String() string {
	if f.value == nil {
		return f.defValue
	}
	return *f.value
}
func (f stringFlag) Set(s string) error {
	if f.validator != nil {
		if err := f.validator(s); err != nil {
			return err
		}
	}
	if f.set != nil {
		*f.set = true
	}
	if f.value != nil {
		*f.value = s
	}
	return nil
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

// registerBoolFlag registers a boolean flag with both long and short forms
func registerBoolFlag(long, short string, set *bool, value *bool, defValue bool, usage string) {
	bf := boolFlag{set, value, defValue}
	flag.Var(bf, long, usage)
	if short != "" {
		flag.Var(bf, short, usage+" (shorthand)")
	}
}

// registerStringFlag registers a string flag with both long and short forms
func registerStringFlag(long, short string, set *bool, value *string, defValue string, validator func(string) error, usage string) {
	sf := stringFlag{set, value, defValue, validator}
	flag.Var(sf, long, usage)
	if short != "" {
		flag.Var(sf, short, usage+" (shorthand)")
	}
}

// InitFlags initializes all command-line flags
func InitFlags() {
	// Output selection flags
	registerBoolFlag("header", "H", &HeaderExplicit, &WithHeader, false, "show token header")
	registerBoolFlag("claims", "c", &ClaimsExplicit, &WithClaims, true, "show token claims (payload)")
	registerBoolFlag("signature", "s", &SignatureExplicit, &WithSignature, false, "show token signature")
	registerBoolFlag("all", "a", nil, &ShowAll, false, "show all token parts and info")

	// Verification flags
	flag.BoolVar(&VerifySignature, "verify", false, "verify token signature (requires --key-file)")
	flag.BoolVar(&VerifySignature, "V", false, "verify token signature (shorthand)")
	registerStringFlag("key-file", "k", &KeyFileExplicit, &KeyFile, "", nil, "key file for signature verification")
	// Keep -key as hidden alias for backward compatibility
	flag.Var(stringFlag{&KeyFileExplicit, &KeyFile, "", nil}, "key", "key file (deprecated: use --key-file)")
	registerBoolFlag("ignore-expiration", "", &IgnoreExpirationExplicit, &IgnoreExpiration, false, "ignore token expiration when verifying")
	// Keep -ignore-exp as hidden alias for backward compatibility
	flag.Var(boolFlag{&IgnoreExpirationExplicit, &IgnoreExpiration, false}, "ignore-exp", "ignore expiration (deprecated: use --ignore-expiration)")

	// Output format flags
	registerStringFlag("output", "o", &FormatExplicit, &OutputFormat, "pretty", validateFormat, "output format: pretty, json, or raw")
	// Keep -format as hidden alias for backward compatibility
	flag.Var(stringFlag{&FormatExplicit, &OutputFormat, "pretty", validateFormat}, "format", "output format (deprecated: use --output)")
	registerBoolFlag("color", "", &ColorExplicit, &OutputColor, true, "colorize output")
	flag.BoolVar(&NoColor, "no-color", false, "disable colored output")
	registerBoolFlag("raw-claims", "", nil, &RawClaims, false, "output only raw claims JSON (for piping)")

	// Expiration flags
	registerBoolFlag("expiration", "e", &ExpirationExplicit, &ShowExpiration, false, "check token expiration status")
	// Keep -expiry as hidden alias for backward compatibility
	flag.Var(boolFlag{&ExpirationExplicit, &ShowExpiration, false}, "expiry", "check expiration (deprecated: use --expiration)")
	registerBoolFlag("decode-signature", "", &DecodeBase64Explicit, &DecodeBase64, false, "decode signature from base64 to hex")
	// Keep -decode-sig as hidden alias for backward compatibility
	flag.Var(boolFlag{&DecodeBase64Explicit, &DecodeBase64, false}, "decode-sig", "decode signature (deprecated: use --decode-signature)")

	// Config flags
	flag.StringVar(&ConfigFile, "config", "", "path to config file")
	flag.BoolVar(&SaveConfig, "save-config", false, "save current settings to config file")

	// Info flags
	flag.BoolVar(&ShowVersion, "version", false, "show version information")
	flag.BoolVar(&ShowHelp, "help", false, "show help message")
	flag.BoolVar(&ShowHelp, "h", false, "show help message (shorthand)")

	// Verbosity flags
	registerBoolFlag("quiet", "q", nil, &Quiet, false, "suppress informational notices")
	registerBoolFlag("verbose", "v", nil, &Verbose, false, "enable verbose output for debugging")

	// Shell completion
	flag.StringVar(&CompletionShell, "completion", "", "generate shell completion script (bash, zsh, fish)")

	// Input parsing
	flag.BoolVar(&Strict, "strict", false, "disable smart token extraction (expect exact JWT input)")

	flag.Usage = PrintUsage
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
