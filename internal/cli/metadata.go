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
	Completions []string
	FileComp    bool
	setFlag     func(*flag.FlagSet, *Flags)
	setExplicit func(*Explicit)
}

// AllOptionSpecs returns the complete option specification table.
// It is intended for tests and external consumers (e.g. completion generation)
// that need metadata without registering flags.
func AllOptionSpecs() []OptionSpec {
	return allSpecs(&Flags{}, &Explicit{})
}

// allSpecs returns the complete option specification table.
// The returned specs can be used for flag registration, explicit tracking,
// usage generation, and shell-completion generation.
func allSpecs(f *Flags, ex *Explicit) []OptionSpec {
	return []OptionSpec{
		// Display
		boolSpec([]string{"header", "H"}, "show token header", "Display", &f.Header, false, func(e *Explicit) { e.Header = true }, ""),
		boolSpec([]string{"claims", "c"}, "show token claims (payload)", "Display", &f.Claims, true, func(e *Explicit) { e.Claims = true }, ""),
		boolSpec([]string{"signature", "s"}, "show token signature", "Display", &f.Signature, false, func(e *Explicit) { e.Signature = true }, ""),
		boolSpec([]string{"all", "a"}, "show all token parts and info", "Display", &f.ShowAll, false, func(e *Explicit) {}, ""),
		boolSpec([]string{"expiration", "e"}, "check token expiration status", "Display", &f.Expiration, false, func(e *Explicit) { e.Expiration = true }, ""),
		boolSpec([]string{"decode-signature"}, "decode signature from base64 to hex", "Display", &f.DecodeSignature, false, func(e *Explicit) { e.DecodeSignature = true }, ""),
		boolSpec([]string{"raw-claims"}, "output only raw claims JSON (for piping to jq)", "Display", &f.RawClaims, false, func(e *Explicit) {}, ""),

		// Verification
		boolSpec([]string{"verify", "V"}, "verify token signature (requires --key-file)", "Verification", &f.VerifySignature, false, func(e *Explicit) {}, ""),
		stringSpec([]string{"key-file", "k"}, "key file for signature verification", "Verification", &f.KeyFile, "", func(e *Explicit) { e.KeyFile = true }, "<file>", nil, true, ""),

		// Output
		stringSpec([]string{"output", "o"}, "output format: pretty, json, or raw", "Output", &f.Format, "pretty", func(e *Explicit) { e.Format = true }, "<format>", []string{"pretty", "json", "raw"}, false, ""),
		boolSpec([]string{"color"}, "colorize output", "Output", &f.Color, true, func(e *Explicit) { e.Color = true }, ""),
		boolSpec([]string{"no-color"}, "disable colored output", "Output", &f.NoColor, false, func(e *Explicit) {}, ""),

		// Configuration
		stringSpec([]string{"config"}, "path to config file", "Configuration", &f.ConfigFile, "", func(e *Explicit) {}, "<file>", nil, true, ""),

		// Input
		boolSpec([]string{"strict"}, "disable smart extraction (expect exact JWT input)", "Input", &f.Strict, false, func(e *Explicit) {}, ""),

		// Other
		boolSpec([]string{"help", "h"}, "show help message", "Other", &f.ShowHelp, false, func(e *Explicit) {}, ""),
		boolSpec([]string{"version"}, "show version information", "Other", &f.ShowVersion, false, func(e *Explicit) {}, ""),
		boolSpec([]string{"quiet", "q"}, "suppress informational notices", "Other", &f.Quiet, false, func(e *Explicit) {}, ""),
		boolSpec([]string{"verbose", "v"}, "enable verbose output for debugging", "Other", &f.Verbose, false, func(e *Explicit) {}, ""),
		stringSpec([]string{"completion"}, "generate shell completion script", "Other", &f.CompletionShell, "", func(e *Explicit) {}, "<shell>", []string{"bash", "zsh", "fish"}, false, ""),

		// Deprecated aliases (not shown in completions)
		stringSpec([]string{"key"}, "key file", "Verification", &f.KeyFile, "", func(e *Explicit) { e.KeyFile = true }, "", nil, false, "--key-file"),
		stringSpec([]string{"format"}, "output format", "Output", &f.Format, "pretty", func(e *Explicit) { e.Format = true }, "", nil, false, "--output"),
		boolSpec([]string{"expiry"}, "check expiration", "Display", &f.Expiration, false, func(e *Explicit) { e.Expiration = true }, "--expiration"),
		boolSpec([]string{"decode-sig"}, "decode signature", "Display", &f.DecodeSignature, false, func(e *Explicit) { e.DecodeSignature = true }, "--decode-signature"),
		boolSpec([]string{"ignore-exp"}, "ignore expiration", "Verification", &f.IgnoreExpiration, false, func(e *Explicit) { e.IgnoreExpiration = true }, "--ignore-expiration"),
	}
}

func boolSpec(names []string, desc, category string, ptr *bool, def bool, setter func(*Explicit), deprecated string) OptionSpec {
	s := OptionSpec{
		Names: names, Description: desc, Category: category, Deprecated: deprecated,
		setFlag: func(fs *flag.FlagSet, f *Flags) {
			for _, name := range names {
				fs.BoolVar(ptr, name, def, desc)
			}
		},
		setExplicit: setter,
	}
	if deprecated != "" {
		s.Description += " (deprecated: use " + deprecated + ")"
	}
	return s
}

func stringSpec(names []string, desc, category string, ptr *string, def string, setter func(*Explicit), argHint string, completions []string, fileComp bool, deprecated string) OptionSpec {
	s := OptionSpec{
		Names: names, Description: desc, Category: category, Deprecated: deprecated, ArgHint: argHint,
		Completions: completions, FileComp: fileComp,
		setFlag: func(fs *flag.FlagSet, f *Flags) {
			for _, name := range names {
				fs.StringVar(ptr, name, def, desc)
			}
		},
		setExplicit: setter,
	}
	if deprecated != "" {
		s.Description += " (deprecated: use " + deprecated + ")"
	}
	return s
}

// InitFlags initializes all command-line flags on the provided FlagSet and Flags struct.
func InitFlags(fs *flag.FlagSet, f *Flags) {
	ex := &Explicit{}
	specs := allSpecs(f, ex)
	for i := range specs {
		specs[i].setFlag(fs, f)
	}
	fs.Usage = PrintUsage
}

// CheckExplicitFlags checks which flags were explicitly set by the user.
func (f *Flags) CheckExplicitFlags(fs *flag.FlagSet, ex *Explicit) error {
	specs := allSpecs(f, ex)
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
			spec.setExplicit(ex)
		}
	})

	if ex.Format {
		if err := validateFormat(f.Format); err != nil {
			return err
		}
	}

	return nil
}

// PrintUsage prints the usage information generated from the option metadata.
func PrintUsage() {
	f := &Flags{}
	ex := &Explicit{}
	specs := allSpecs(f, ex)

	// Collect categories and max option width.
	categories := []string{"Display", "Verification", "Output", "Configuration", "Input", "Other"}
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

// GenerateBashCompletion returns a bash completion script generated from option metadata.
func GenerateBashCompletion() string {
	f := &Flags{}
	ex := &Explicit{}
	specs := allSpecs(f, ex)

	var opts []string
	var cases []string
	for _, spec := range specs {
		if spec.Deprecated != "" {
			continue
		}
		for _, name := range spec.Names {
			if len(name) == 1 {
				opts = append(opts, "-"+name)
			} else {
				opts = append(opts, "--"+name)
			}
		}
		if spec.FileComp {
			for _, name := range spec.Names {
				cases = append(cases, fmt.Sprintf("        --%s)\n            COMPREPLY=( $(compgen -f -- \"${cur}\") )\n            return 0\n            ;;", name))
				if len(name) == 1 {
					cases = append(cases, fmt.Sprintf("        -%s)\n            COMPREPLY=( $(compgen -f -- \"${cur}\") )\n            return 0\n            ;;", name))
				}
			}
		}
		if len(spec.Completions) > 0 {
			comps := strings.Join(spec.Completions, " ")
			for _, name := range spec.Names {
				cases = append(cases, fmt.Sprintf("        --%s)\n            COMPREPLY=( $(compgen -W \"%s\" -- \"${cur}\") )\n            return 0\n            ;;", name, comps))
				if len(name) == 1 {
					cases = append(cases, fmt.Sprintf("        -%s)\n            COMPREPLY=( $(compgen -W \"%s\" -- \"${cur}\") )\n            return 0\n            ;;", name, comps))
				}
			}
		}
	}

	return fmt.Sprintf(`# jwtdebug bash completion
_jwtdebug() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="%s"

    case "${prev}" in
%s
    esac

    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi

    COMPREPLY=( $(compgen -f -- "${cur}") )
}

complete -F _jwtdebug jwtdebug
`, strings.Join(opts, " "), strings.Join(cases, "\n"))
}

// GenerateZshCompletion returns a zsh completion script generated from option metadata.
func GenerateZshCompletion() string {
	f := &Flags{}
	ex := &Explicit{}
	specs := allSpecs(f, ex)

	var entries []string
	for _, spec := range specs {
		if spec.Deprecated != "" {
			continue
		}
		var quotedNames []string
		for _, name := range spec.Names {
			if len(name) == 1 {
				quotedNames = append(quotedNames, "-"+name)
			} else {
				quotedNames = append(quotedNames, "--"+name)
			}
		}
		nameGroup := strings.Join(quotedNames, ",")
		entry := fmt.Sprintf("        '%s[%s]'", nameGroup, spec.Description)
		if spec.FileComp {
			entry = fmt.Sprintf("        '%s[%s]:file:_files'", nameGroup, spec.Description)
		} else if len(spec.Completions) > 0 {
			entry = fmt.Sprintf("        '%s[%s]:format:(%s)'", nameGroup, spec.Description, strings.Join(spec.Completions, " "))
		}
		entries = append(entries, entry)
	}
	entries = append(entries, "        '*:token:_files'")

	return fmt.Sprintf(`#compdef jwtdebug

_jwtdebug() {
    local -a opts
    opts=(
%s
    )

    _arguments -s $opts
}

_jwtdebug "$@"
`, strings.Join(entries, "\n"))
}

// GenerateFishCompletion returns a fish completion script generated from option metadata.
func GenerateFishCompletion() string {
	f := &Flags{}
	ex := &Explicit{}
	specs := allSpecs(f, ex)

	var lines []string
	lines = append(lines, "# jwtdebug fish completion")
	lines = append(lines, "")
	lines = append(lines, "complete -c jwtdebug -f")

	for _, spec := range specs {
		if spec.Deprecated != "" {
			continue
		}
		var shorts []string
		var longs []string
		for _, name := range spec.Names {
			if len(name) == 1 {
				shorts = append(shorts, name)
			} else {
				longs = append(longs, name)
			}
		}
		parts := []string{"complete -c jwtdebug"}
		for _, s := range shorts {
			parts = append(parts, "-s "+s)
		}
		for _, l := range longs {
			parts = append(parts, "-l "+l)
		}
		if spec.FileComp {
			parts = append(parts, "-r -F")
		}
		if len(spec.Completions) > 0 {
			parts = append(parts, "-r -a '"+strings.Join(spec.Completions, " ")+"'")
		}
		parts = append(parts, "-d '"+spec.Description+"'")
		lines = append(lines, strings.Join(parts, " "))
	}

	return strings.Join(lines, "\n") + "\n"
}
