package jwtdebug

import (
	"errors"
	"fmt"
	"strings"
)

var errHelp = errors.New("help requested")

type flags struct {
	keyFile          string
	algorithm        string
	header           bool
	claims           bool
	signature        bool
	expiration       bool
	ignoreExpiration bool
	verifySignature  bool
	showVersion      bool
	quiet            bool
	verbose          bool
	rawClaims        bool
	strict           bool
}

type optionKind uint8

const (
	boolOption optionKind = iota
	optionalBoolOption
	stringOption
)

type optionSpec struct {
	long   string
	short  byte
	kind   optionKind
	hidden bool
	usage  string
}

var optionSpecs = []optionSpec{
	{long: "header", short: 'H', kind: boolOption, usage: "  -H, --header                 show token header"},
	{long: "claims", short: 'c', kind: optionalBoolOption, usage: "  -c, --claims[=<CLAIMS>]      show token claims (payload) [default: true] [possible values: true, false]"},
	{long: "signature", short: 's', kind: boolOption, usage: "  -s, --signature              show token signature"},
	{long: "all", short: 'a', kind: boolOption, usage: "  -a, --all                    show all token parts and info"},
	{long: "expiration", short: 'e', kind: boolOption, usage: "  -e, --expiration             check token expiration status"},
	{long: "raw-claims", kind: boolOption, usage: "      --raw-claims             output only raw claims JSON (for piping to jq)"},
	{long: "verify", short: 'V', kind: boolOption, usage: "  -V, --verify                 verify token signature (requires --key-file)"},
	{long: "algorithm", kind: stringOption, usage: "      --algorithm <algorithm>  expected signing algorithm for verification"},
	{long: "key-file", short: 'k', kind: stringOption, usage: "  -k, --key-file <file>        key file for signature verification"},
	{long: "ignore-expiration", kind: boolOption, usage: "      --ignore-expiration      ignore token expiration when verifying"},
	{long: "strict", kind: boolOption, usage: "      --strict                 disable smart extraction (expect exact JWT input)"},
	{long: "version", kind: boolOption, usage: "      --version                show version information"},
	{long: "quiet", short: 'q', kind: boolOption, usage: "  -q, --quiet                  suppress informational notices"},
	{long: "verbose", short: 'v', kind: boolOption, usage: "  -v, --verbose                enable verbose output for debugging"},
	{long: "help", short: 'h', kind: boolOption, usage: "  -h, --help                   Print help"},
	{long: "key", kind: stringOption, hidden: true},
	{long: "expiry", kind: boolOption, hidden: true},
	{long: "ignore-exp", kind: boolOption, hidden: true},
}

type parsedArgs struct {
	flags    flags
	tokens   []string
	warnings []string
}

type parseState struct {
	flags             flags
	tokens            []string
	deprecatedKey     string
	usedDeprecatedKey bool
	deprecatedExpiry  bool
	deprecatedIgnore  bool
	showAll           bool
}

func parseArgs(args []string) (parsedArgs, error) {
	state := parseState{flags: flags{claims: true}}
	optionsDone := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if optionsDone || arg == "-" || !strings.HasPrefix(arg, "-") {
			state.tokens = append(state.tokens, arg)
			continue
		}
		if arg == "--" {
			optionsDone = true
			continue
		}

		var err error
		if strings.HasPrefix(arg, "--") {
			i, err = parseNamedOption(args, i, strings.TrimPrefix(arg, "--"), &state)
		} else {
			name, _, _ := strings.Cut(strings.TrimPrefix(arg, "-"), "=")
			if findLongOption(name) != nil {
				i, err = parseNamedOption(args, i, strings.TrimPrefix(arg, "-"), &state)
			} else {
				i, err = parseShortOptions(args, i, strings.TrimPrefix(arg, "-"), &state)
			}
		}
		if err != nil {
			return parsedArgs{}, err
		}
	}

	if state.flags.algorithm != "" && !state.flags.verifySignature {
		return parsedArgs{}, errors.New("--algorithm requires --verify")
	}

	if state.flags.keyFile == "" {
		state.flags.keyFile = state.deprecatedKey
	}
	state.flags.expiration = state.flags.expiration || state.deprecatedExpiry
	state.flags.ignoreExpiration = state.flags.ignoreExpiration || state.deprecatedIgnore
	if state.showAll {
		state.flags.header = true
		state.flags.claims = true
		state.flags.signature = true
		state.flags.expiration = true
	}

	var warnings []string
	if state.usedDeprecatedKey {
		warnings = append(warnings, "Warning: --key is deprecated, use --key-file")
	}
	if state.deprecatedExpiry {
		warnings = append(warnings, "Warning: --expiry is deprecated, use --expiration")
	}
	if state.deprecatedIgnore {
		warnings = append(warnings, "Warning: --ignore-exp is deprecated, use --ignore-expiration")
	}

	return parsedArgs{
		flags:    state.flags,
		tokens:   state.tokens,
		warnings: warnings,
	}, nil
}

func parseNamedOption(args []string, index int, raw string, state *parseState) (int, error) {
	name, value, hasValue := strings.Cut(raw, "=")
	spec := findLongOption(name)
	if spec == nil {
		return index, fmt.Errorf("unexpected argument --%s", name)
	}

	return applyOption(args, index, *spec, value, hasValue, state)
}

func parseShortOptions(args []string, index int, raw string, state *parseState) (int, error) {
	for position := 0; position < len(raw); position++ {
		spec := findShortOption(raw[position])
		if spec == nil {
			return index, fmt.Errorf("unknown shorthand flag: %q", "-"+string(raw[position]))
		}

		value := ""
		hasValue := false
		remainder := raw[position+1:]
		switch spec.kind {
		case stringOption:
			if remainder != "" {
				value = strings.TrimPrefix(remainder, "=")
				hasValue = true
				position = len(raw)
			}
		case optionalBoolOption:
			if strings.HasPrefix(remainder, "=") {
				value = strings.TrimPrefix(remainder, "=")
				hasValue = true
				position = len(raw)
			}
		}

		var err error
		index, err = applyOption(args, index, *spec, value, hasValue, state)
		if err != nil {
			return index, err
		}
		if spec.kind == stringOption {
			return index, nil
		}
	}

	return index, nil
}

func applyOption(
	args []string,
	index int,
	spec optionSpec,
	value string,
	hasValue bool,
	state *parseState,
) (int, error) {
	switch spec.kind {
	case boolOption:
		if hasValue {
			return index, fmt.Errorf("option --%s does not take a value", spec.long)
		}
		value = "true"
	case optionalBoolOption:
		if !hasValue {
			value = "true"
		}
		if value != "true" && value != "false" {
			return index, fmt.Errorf("invalid value %q for --%s: expected true or false", value, spec.long)
		}
	case stringOption:
		if !hasValue {
			if index+1 >= len(args) {
				return index, fmt.Errorf("option --%s requires a value", spec.long)
			}
			index++
			value = args[index]
		}
		if value == "" {
			return index, fmt.Errorf("option --%s requires a value", spec.long)
		}
	default:
		return index, fmt.Errorf("unsupported option --%s", spec.long)
	}

	if err := setOption(state, spec.long, value); err != nil {
		return index, err
	}
	return index, nil
}

func setOption(state *parseState, name, value string) error {
	enabled := value == "true"
	switch name {
	case "header":
		state.flags.header = enabled
	case "claims":
		state.flags.claims = enabled
	case "signature":
		state.flags.signature = enabled
	case "all":
		state.showAll = enabled
	case "expiration":
		state.flags.expiration = enabled
	case "raw-claims":
		state.flags.rawClaims = enabled
	case "verify":
		state.flags.verifySignature = enabled
	case "algorithm":
		state.flags.algorithm = value
	case "key-file":
		state.flags.keyFile = value
	case "ignore-expiration":
		state.flags.ignoreExpiration = enabled
	case "strict":
		state.flags.strict = enabled
	case "version":
		state.flags.showVersion = enabled
	case "quiet":
		state.flags.quiet = enabled
	case "verbose":
		state.flags.verbose = enabled
	case "help":
		return errHelp
	case "key":
		state.deprecatedKey = value
		state.usedDeprecatedKey = true
	case "expiry":
		state.deprecatedExpiry = enabled
	case "ignore-exp":
		state.deprecatedIgnore = enabled
	default:
		return fmt.Errorf("unsupported option --%s", name)
	}
	return nil
}

func findLongOption(name string) *optionSpec {
	for i := range optionSpecs {
		if optionSpecs[i].long == name {
			return &optionSpecs[i]
		}
	}
	return nil
}

func findShortOption(short byte) *optionSpec {
	for i := range optionSpecs {
		if optionSpecs[i].short == short {
			return &optionSpecs[i]
		}
	}
	return nil
}

func printHelp(out *output) {
	out.stdoutText("JWT Debug Tool - Decode and analyze JWT tokens\n\n")
	out.stdoutText("Usage: jwtdebug [OPTIONS] [token]...\n\n")
	out.stdoutText("Arguments:\n  [token]...\n\nOptions:\n")
	for _, spec := range optionSpecs {
		if !spec.hidden {
			out.stdoutLine("%s", spec.usage)
		}
	}
	out.stdoutText(`
If no token is provided, jwtdebug reads from stdin.

Examples:
  jwtdebug eyJhbGci...              # Decode a token
  echo "Bearer eyJ..." | jwtdebug   # Read from pipe
  pbpaste | jwtdebug                # Decode from the macOS clipboard
  jwtdebug -a token                 # Show all token parts and expiration
  jwtdebug -V -k pub.pem --algorithm RS256 token
                                    # Verify with a trusted algorithm and key
  jwtdebug --raw-claims token | jq  # Pipe claims to jq

Exit codes:
  0  Success
  1  General error
  2  Invalid token format
  3  Signature verification failed

For more information, see: https://github.com/rselbach/jwtdebug
`)
}
