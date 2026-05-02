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

// Flags holds all CLI flag values
type Flags struct {
	KeyFile          string
	Header           bool
	Claims           bool
	Signature        bool
	Expiration       bool
	IgnoreExpiration bool
	VerifySignature  bool
	ShowAll          bool
	ShowVersion      bool
	Quiet            bool
	Verbose          bool
	RawClaims        bool
	ShowHelp         bool
	Strict           bool
}

// Parse parses command-line arguments into Flags and remaining positional arguments.
func Parse(args []string) (*Flags, []string, error) {
	f := &Flags{}
	fs := flag.NewFlagSet("jwtdebug", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	InitFlags(fs, f)

	if err := fs.Parse(args); err != nil {
		return nil, nil, err
	}

	if err := checkExplicitFlags(fs, f); err != nil {
		return nil, nil, err
	}

	return f, fs.Args(), nil
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
