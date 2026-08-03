package jwtdebug

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	exitSuccess          = 0
	exitError            = 1
	exitInvalidToken     = 2
	exitVerificationFail = 3
	maxTokenInputSize    = 1024 * 1024
)

type verifierState struct {
	initialized bool
	verifier    *verifier
	err         error
}

type tokenProcessor struct {
	flags    flags
	verifier verifierState
	out      *output
}

func run(args []string, stdin io.Reader, stdinIsTerminal bool, out *output) int {
	parsed, err := parseArgs(args)
	if err != nil {
		if errors.Is(err, errHelp) {
			printHelp(out)
			return exitSuccess
		}
		out.stderrText(fmt.Sprintf(
			"error: %v\n\nFor more information, try '--help'.\n",
			err,
		))
		return exitError
	}

	for _, warning := range parsed.warnings {
		out.stderrLine("%s", warning)
	}
	if parsed.flags.showVersion {
		printVersion(parsed.flags, out)
		return exitSuccess
	}

	processor := tokenProcessor{flags: parsed.flags, out: out}
	return processor.processInputs(parsed.tokens, stdin, stdinIsTerminal)
}

func printVersion(options flags, out *output) {
	out.stdoutLine("jwtdebug version %s", resolvedVersion())
	if options.verbose || commit != "unknown" {
		out.stdoutLine("  commit:     %s", commit)
		out.stdoutLine("  built:      %s", buildDate)
	}
}

func (p *tokenProcessor) processInputs(
	tokens []string,
	stdin io.Reader,
	stdinIsTerminal bool,
) int {
	if len(tokens) == 0 {
		return p.processStdin(stdin, stdinIsTerminal, false)
	}
	if len(tokens) == 1 && tokens[0] == "-" {
		return p.processStdin(stdin, stdinIsTerminal, true)
	}

	exitCode := exitSuccess
	for _, token := range tokens {
		if token == "-" {
			exitCode = retainFirstFailure(
				exitCode,
				p.processStdin(stdin, stdinIsTerminal, true),
			)
			continue
		}
		exitCode = retainFirstFailure(exitCode, p.processToken(token))
	}
	return exitCode
}

func retainFirstFailure(seen, current int) int {
	if seen == exitSuccess {
		return current
	}
	return seen
}

func (p *tokenProcessor) processToken(input string) int {
	if len(strings.TrimSpace(input)) > maxTokenInputSize {
		p.out.stderrLine("Error: token input exceeds maximum size of %d bytes", maxTokenInputSize)
		return exitInvalidToken
	}
	parsed, err := resolveToken(input, p.flags.strict)
	if err != nil {
		p.out.stderrLine("Error: %v", err)
		return exitInvalidToken
	}
	p.logParsedToken(input, parsed)

	if p.flags.verifySignature {
		p.logVerbose(
			"verifying signature with key file %q (ignore-expiration=%t)",
			p.flags.keyFile,
			p.flags.ignoreExpiration,
		)
		if !p.verifier.initialized {
			p.verifier.initialized = true
			p.verifier.verifier, p.verifier.err = newVerifier(
				p.flags.keyFile,
				p.flags.algorithm,
				p.flags.ignoreExpiration,
			)
			if p.verifier.verifier != nil && p.verifier.verifier.weakKeyWarning != nil {
				warning := p.verifier.verifier.weakKeyWarning
				p.out.stderrLine(
					"Warning: HMAC key is %d bytes; RFC 7518 requires at least %d for this algorithm",
					warning.actual,
					warning.minimum,
				)
			}
		}
		if p.verifier.err != nil {
			p.printVerificationFailure(p.verifier.err)
			return exitVerificationFail
		}
		if err := p.verifier.verifier.verify(parsed, time.Now()); err != nil {
			p.printVerificationFailure(err)
			return exitVerificationFail
		}
		p.logVerbose("signature verification succeeded")
	}

	if p.flags.rawClaims {
		data, err := prettyJSON(parsed.claims)
		if err != nil {
			p.out.stderrLine("Error: failed to encode claims as JSON: %v", err)
			return exitError
		}
		p.out.stdoutLine("%s", data)
		return exitSuccess
	}

	if !p.flags.verifySignature && !p.flags.quiet {
		p.out.stderrLine(
			"Note: claims are unverified. Use --verify --key-file --algorithm to validate.",
		)
	}
	if p.flags.header {
		if err := printJSONBlock("HEADER", parsed.header, p.out); err != nil {
			p.out.stderrLine("Error: failed to encode header as JSON: %v", err)
			return exitError
		}
	}
	if p.flags.claims {
		if err := printJSONBlock("CLAIMS", parsed.claims, p.out); err != nil {
			p.out.stderrLine("Error: failed to encode claims as JSON: %v", err)
			return exitError
		}
	}
	if p.flags.signature {
		if err := printJSONBlock("SIGNATURE", map[string]any{"raw": parsed.signature}, p.out); err != nil {
			p.out.stderrLine("Error: failed to encode signature as JSON: %v", err)
			return exitError
		}
	}
	if p.flags.expiration {
		checkExpiration(parsed.claims, time.Now(), p.out)
	}
	if p.flags.verifySignature {
		p.out.stdoutLine("Signature verified successfully")
	}
	return exitSuccess
}

func printJSONBlock(name string, value any, out *output) error {
	data, err := prettyJSON(value)
	if err != nil {
		return err
	}
	out.stdoutLine("%s:", name)
	out.stdoutLine("%s", data)
	out.stdoutLine("")
	return nil
}

func (p *tokenProcessor) printVerificationFailure(err error) {
	p.out.stderrLine("Signature verification failed: %v", err)
}

func (p *tokenProcessor) logParsedToken(input string, parsed parsedToken) {
	if !p.flags.verbose {
		return
	}

	trimmed := strings.TrimSpace(input)
	if trimmed != parsed.raw {
		p.logVerbose(
			"extracted JWT from input (%d bytes -> %d bytes)",
			len(trimmed),
			len(parsed.raw),
		)
	} else {
		p.logVerbose("using token (%d bytes)", len(parsed.raw))
	}

	algorithm := "<missing>"
	if value, ok := parsed.header["alg"]; ok {
		algorithm = formatJSONValue(value)
	}
	p.logVerbose("header alg=%s", algorithm)
}

func (p *tokenProcessor) logVerbose(format string, args ...any) {
	if p.flags.verbose {
		p.out.stderrLine("verbose: "+format, args...)
	}
}

func (p *tokenProcessor) processStdin(
	stdin io.Reader,
	stdinIsTerminal bool,
	explicit bool,
) int {
	if stdinIsTerminal {
		if !explicit {
			printUsageHint(p.out)
			return exitError
		}
		if !p.flags.quiet {
			p.out.stderrLine("Reading token from stdin... (press Ctrl+D when done)")
		}
	}

	reader := bufio.NewReader(stdin)
	hasToken := false
	exitCode := exitSuccess
	for {
		line, tooLarge, err := readInputLine(reader)
		if tooLarge {
			hasToken = true
			p.out.stderrLine("Error: token input exceeds maximum size of %d bytes", maxTokenInputSize)
			exitCode = retainFirstFailure(exitCode, exitInvalidToken)
		}
		line = strings.TrimSpace(line)
		if !tooLarge && line != "" {
			hasToken = true
			exitCode = retainFirstFailure(exitCode, p.processToken(line))
		}

		switch {
		case err == nil:
			continue
		case errors.Is(err, io.EOF):
			if !hasToken {
				p.out.stderrLine("Error: no token provided on stdin")
				return exitError
			}
			return exitCode
		default:
			p.out.stderrLine("Error: failed to read stdin: %v", err)
			return retainFirstFailure(exitCode, exitError)
		}
	}
}

func readInputLine(reader *bufio.Reader) (string, bool, error) {
	var line []byte
	tooLarge := false
	for {
		fragment, err := reader.ReadSlice('\n')
		if !tooLarge {
			// Leave room for a line ending; processToken enforces the exact
			// post-trimming token limit.
			if len(line)+len(fragment) > maxTokenInputSize+2 {
				tooLarge = true
				line = nil
			} else {
				line = append(line, fragment...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return string(line), tooLarge, err
	}
}

func printUsageHint(out *output) {
	out.stderrText("Error: no token provided\n\n" +
		"Usage: jwtdebug [options] <token>\n" +
		"       jwtdebug [options] -           # read from stdin\n" +
		"       command | jwtdebug [options]   # read from pipe\n\n" +
		"Run 'jwtdebug --help' for more information.\n")
}
