package cli

import (
	"flag"
	"io"
)

// Version information will be set at build time
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// Options holds runtime settings.
type Options struct {
	KeyFile          string
	Header           bool
	Claims           bool
	Signature        bool
	Expiration       bool
	IgnoreExpiration bool
}

// Flags holds all CLI flag values
type Flags struct {
	Options
	VerifySignature bool
	ShowAll         bool
	ShowVersion     bool
	Quiet           bool
	Verbose         bool
	RawClaims       bool
	ShowHelp        bool
	Strict          bool
}

// Explicit tracks which flags were explicitly set by the user
type Explicit struct {
	Header           bool
	Claims           bool
	Signature        bool
	KeyFile          bool
	Expiration       bool
	IgnoreExpiration bool
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
