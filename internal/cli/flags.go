package cli

import (
	"flag"
	"fmt"
	"io"

	"github.com/fatih/color"
)

// Version information will be set at build time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Options holds runtime settings shared between CLI and config.
type Options struct {
	Format           string
	Color            bool
	KeyFile          string
	Header           bool
	Claims           bool
	Signature        bool
	Expiration       bool
	DecodeSignature  bool
	IgnoreExpiration bool
}

// Flags holds all CLI flag values
type Flags struct {
	Options
	VerifySignature bool
	NoColor         bool
	ShowAll         bool
	ConfigFile      string
	SaveConfig      bool
	ShowVersion     bool
	Quiet           bool
	Verbose         bool
	RawClaims       bool
	ShowHelp        bool
	CompletionShell string
	Strict          bool
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
	DecodeSignature  bool
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

// Parse parses command-line arguments into Flags, Explicit tracking, and remaining positional arguments.
func Parse(args []string) (*Flags, *Explicit, []string, error) {
	f := &Flags{}
	ex := &Explicit{}
	fs := flag.NewFlagSet("jwtdebug", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	InitFlags(fs, f)

	if err := fs.Parse(args); err != nil {
		return nil, nil, nil, err
	}

	if err := f.CheckExplicitFlags(fs, ex); err != nil {
		return nil, nil, nil, err
	}

	return f, ex, fs.Args(), nil
}

// ApplyAllFlag enables all output options if the -all flag is set
func (f *Flags) ApplyAllFlag() {
	if f.ShowAll {
		f.Header = true
		f.Claims = true
		f.Signature = true
		f.Expiration = true
	}
}

// ApplyColorSettings syncs --no-color into Color and the global color.NoColor
func (f *Flags) ApplyColorSettings() {
	if f.NoColor {
		f.Color = false
	}
	color.NoColor = !f.Color
}
