package cli

import (
	"flag"
	"fmt"
	"os"
)

// Version information will be set at build time
var Version = "dev"

var (
	// Exported flag variables
	WithHeader       bool
	WithClaims       bool
	WithSignature    bool
	VerifySignature  bool
	KeyFile          string
	OutputFormat     string
	OutputColor      bool
	ShowExpiration   bool
	ShowAll          bool
	DecodeBase64     bool
	IgnoreExpiration bool
	ConfigFile       string
	SaveConfig       bool
	ShowVersion      bool

	// Track if flags were explicitly set by user
	HeaderExplicit         bool
	ClaimsExplicit         bool
	SignatureExplicit      bool
	KeyFileExplicit        bool
	FormatExplicit         bool
	ColorExplicit          bool
	ExpirationExplicit     bool
	DecodeBase64Explicit   bool
	IgnoreExpirationExplicit bool
)

// Custom flag types to track if flags were set
type boolFlag struct {
	set   *bool
	value *bool
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
		if s == "true" {
			*f.value = true
		} else {
			*f.value = false
		}
	}
	return nil
}

type stringFlag struct {
	set      *bool
	value    *string
	defValue string
}

func (f stringFlag) String() string {
	if f.value == nil {
		return f.defValue
	}
	return *f.value
}
func (f stringFlag) Set(s string) error {
	if f.set != nil {
		*f.set = true
	}
	if f.value != nil {
		*f.value = s
	}
	return nil
}

// InitFlags initializes all command-line flags
func InitFlags() {
	// Set default values first
	WithClaims = true
	OutputFormat = "pretty"
	OutputColor = true
	
	// Define custom flags that track if they were set (with default values)
	flag.Var(boolFlag{&HeaderExplicit, &WithHeader, false}, "header", "show token header")
	flag.Var(boolFlag{&ClaimsExplicit, &WithClaims, true}, "claims", "show token claims (payload)")
	flag.Var(boolFlag{&SignatureExplicit, &WithSignature, false}, "sig", "show token signature")
	
	// These flags don't need tracking but are included for completeness
	flag.BoolVar(&VerifySignature, "verify", false, "verify token signature (requires -key)")
	flag.BoolVar(&ShowAll, "all", false, "show all token parts and info")
	flag.BoolVar(&SaveConfig, "save-config", false, "save current settings to config file")
	
	// These flags need tracking for config file integration
	flag.Var(stringFlag{&KeyFileExplicit, &KeyFile, ""}, "key", "key file for signature verification")
	flag.Var(stringFlag{&FormatExplicit, &OutputFormat, "pretty"}, "format", "output format: pretty, json, yaml, or raw")
	flag.Var(boolFlag{&ColorExplicit, &OutputColor, true}, "color", "colorize output")
	flag.Var(boolFlag{&ExpirationExplicit, &ShowExpiration, false}, "expiry", "check token expiration status")
	flag.Var(boolFlag{&DecodeBase64Explicit, &DecodeBase64, false}, "decode-sig", "decode signature from base64")
	flag.Var(boolFlag{&IgnoreExpirationExplicit, &IgnoreExpiration, false}, "ignore-exp", "ignore token expiration when verifying")
	
	// Config file flag
	flag.StringVar(&ConfigFile, "config", "", "path to config file")
	
	// Version flag
	flag.BoolVar(&ShowVersion, "version", false, "show version information")
	
	flag.Usage = PrintUsage
}

// PrintUsage prints the usage information
func PrintUsage() {
	fmt.Fprintf(os.Stderr, "JWT Debug Tool - Decode and analyze JWT tokens\n\n")
	fmt.Fprintf(os.Stderr, "Usage: jwtdebug [options] [token]\n")
	fmt.Fprintf(os.Stderr, "  If no token is provided, jwtdebug reads from stdin\n\n")
	fmt.Fprintf(os.Stderr, "Options:\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nExamples:\n")
	fmt.Fprintf(os.Stderr, "  jwtdebug eyJhbGci...rest_of_token\n")
	fmt.Fprintf(os.Stderr, "  echo \"Bearer eyJhbGci...\" | jwtdebug\n")
	fmt.Fprintf(os.Stderr, "  jwtdebug -all -key pubkey.pem eyJhbGci...rest_of_token\n")
	fmt.Fprintf(os.Stderr, "  jwtdebug -format yaml -save-config  # Save settings to config file\n")
}

// EnableAllOutputs enables all output options if the -all flag is set
func EnableAllOutputs() {
	if ShowAll {
		WithHeader = true
		WithClaims = true 
		WithSignature = true
		ShowExpiration = true
	}
}
