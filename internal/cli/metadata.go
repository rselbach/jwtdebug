package cli

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fatih/color"
)

// OptionSpec describes a single command-line option and how to register it.
type OptionSpec struct {
	Names       []string
	Description string
	Category    string
	Deprecated  string
	ArgHint     string
	setFlag     func(*flag.FlagSet, *Flags)
}

// AllOptionSpecs returns the complete option specification table.
func AllOptionSpecs() []OptionSpec {
	return allSpecs(&Flags{})
}

// allSpecs returns the complete option specification table.
func allSpecs(f *Flags) []OptionSpec {
	return []OptionSpec{
		// Display
		boolSpec([]string{"header", "H"}, "show token header", "Display", &f.Header, false, ""),
		boolSpec([]string{"claims", "c"}, "show token claims (payload)", "Display", &f.Claims, true, ""),
		boolSpec([]string{"signature", "s"}, "show token signature", "Display", &f.Signature, false, ""),
		boolSpec([]string{"all", "a"}, "show all token parts and info", "Display", &f.ShowAll, false, ""),
		boolSpec([]string{"expiration", "e"}, "check token expiration status", "Display", &f.Expiration, false, ""),
		boolSpec([]string{"raw-claims"}, "output only raw claims JSON (for piping to jq)", "Display", &f.RawClaims, false, ""),

		// Verification
		boolSpec([]string{"verify", "V"}, "verify token signature (requires --key-file)", "Verification", &f.VerifySignature, false, ""),
		stringSpec([]string{"key-file", "k"}, "key file for signature verification", "Verification", &f.KeyFile, "", "<file>", ""),
		boolSpec([]string{"ignore-expiration"}, "ignore token expiration when verifying", "Verification", &f.IgnoreExpiration, false, ""),

		// Input
		boolSpec([]string{"strict"}, "disable smart extraction (expect exact JWT input)", "Input", &f.Strict, false, ""),

		// Other
		boolSpec([]string{"help", "h"}, "show help message", "Other", &f.ShowHelp, false, ""),
		boolSpec([]string{"version"}, "show version information", "Other", &f.ShowVersion, false, ""),
		boolSpec([]string{"quiet", "q"}, "suppress informational notices", "Other", &f.Quiet, false, ""),
		boolSpec([]string{"verbose", "v"}, "enable verbose output for debugging", "Other", &f.Verbose, false, ""),

		// Deprecated aliases
		stringSpec([]string{"key"}, "key file", "Verification", &f.KeyFile, "", "", "--key-file"),
		boolSpec([]string{"expiry"}, "check expiration", "Display", &f.Expiration, false, "--expiration"),
		boolSpec([]string{"ignore-exp"}, "ignore expiration", "Verification", &f.IgnoreExpiration, false, "--ignore-expiration"),
	}
}

func boolSpec(names []string, desc, category string, ptr *bool, def bool, deprecated string) OptionSpec {
	s := OptionSpec{
		Names: names, Description: desc, Category: category, Deprecated: deprecated,
		setFlag: func(fs *flag.FlagSet, f *Flags) {
			for _, name := range names {
				fs.BoolVar(ptr, name, def, desc)
			}
		},
	}
	if deprecated != "" {
		s.Description += " (deprecated: use " + deprecated + ")"
	}
	return s
}

func stringSpec(names []string, desc, category string, ptr *string, def string, argHint string, deprecated string) OptionSpec {
	s := OptionSpec{
		Names: names, Description: desc, Category: category, Deprecated: deprecated, ArgHint: argHint,
		setFlag: func(fs *flag.FlagSet, f *Flags) {
			for _, name := range names {
				fs.StringVar(ptr, name, def, desc)
			}
		},
	}
	if deprecated != "" {
		s.Description += " (deprecated: use " + deprecated + ")"
	}
	return s
}

// InitFlags initializes all command-line flags on the provided FlagSet and Flags struct.
func InitFlags(fs *flag.FlagSet, f *Flags) {
	specs := allSpecs(f)
	for i := range specs {
		specs[i].setFlag(fs, f)
	}
	fs.Usage = PrintUsage
}

// checkExplicitFlags prints deprecation warnings for explicitly-set deprecated flags.
func checkExplicitFlags(fs *flag.FlagSet, f *Flags) error {
	specs := allSpecs(f)
	registry := make(map[string]OptionSpec, len(specs)*2)
	for _, spec := range specs {
		for _, name := range spec.Names {
			registry[name] = spec
		}
	}

	fs.Visit(func(fl *flag.Flag) {
		if spec, ok := registry[fl.Name]; ok {
			if spec.Deprecated != "" {
				fmt.Fprintf(color.Error, "Warning: --%s is deprecated, use %s\n", fl.Name, spec.Deprecated)
			}
		}
	})

	return nil
}

// PrintUsage prints the usage information generated from the option metadata.
func PrintUsage() {
	f := &Flags{}
	specs := allSpecs(f)

	// Collect categories and max option width.
	categories := []string{"Display", "Verification", "Input", "Other"}
	byCategory := make(map[string][]OptionSpec)
	maxLen := 0
	for _, spec := range specs {
		if spec.Deprecated != "" {
			continue
		}
		byCategory[spec.Category] = append(byCategory[spec.Category], spec)
		line := formatOptLine(spec.Names, spec.ArgHint)
		if len(line) > maxLen {
			maxLen = len(line)
		}
	}

	fmt.Fprintf(color.Error, "JWT Debug Tool - Decode and analyze JWT tokens\n\n")
	fmt.Fprintf(color.Error, "Usage: jwtdebug [options] [token]\n")
	fmt.Fprintf(color.Error, "       jwtdebug [options] -           # read from stdin explicitly\n")
	fmt.Fprintf(color.Error, "       command | jwtdebug [options]   # read from pipe\n\n")
	fmt.Fprintf(color.Error, "If no token is provided, jwtdebug reads from stdin.\n")

	for _, cat := range categories {
		catSpecs := byCategory[cat]
		if len(catSpecs) == 0 {
			continue
		}
		fmt.Fprintf(color.Error, "\n  %s:\n", cat)
		for _, spec := range catSpecs {
			optLine := formatOptLine(spec.Names, spec.ArgHint)
			fmt.Fprintf(color.Error, "    %-*s  %s\n", maxLen, optLine, spec.Description)
		}
	}

	fmt.Fprintf(color.Error, `\nExamples:
  jwtdebug eyJhbGci...              # Decode a token
  echo "Bearer eyJ..." | jwtdebug   # Read from pipe (strips "Bearer " prefix)
  pbpaste | jwtdebug                # Decode token from clipboard (macOS)
  jwtdebug -a token                 # Show all parts (header, claims, signature, expiry)
  jwtdebug -V -k pub.pem token      # Verify signature with public key
  jwtdebug --raw-claims token | jq  # Pipe claims to jq

Exit Codes:
  0  Success
  1  General error
  2  Invalid token format
  3  Signature verification failed

For more information, see: https://github.com/rselbach/jwtdebug
`)
}

func formatOptLine(names []string, argHint string) string {
	var parts []string
	for _, name := range names {
		if len(name) == 1 {
			parts = append(parts, "-"+name)
		} else {
			parts = append(parts, "--"+name)
		}
	}
	line := strings.Join(parts, ", ")
	if argHint != "" {
		line += " " + argHint
	}
	return line
}
