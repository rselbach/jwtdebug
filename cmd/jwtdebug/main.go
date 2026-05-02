package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/constants"
	"github.com/rselbach/jwtdebug/internal/parser"
	"github.com/rselbach/jwtdebug/internal/printer"
	"github.com/rselbach/jwtdebug/internal/verification"
)

func main() {
	os.Exit(run())
}

func run() int {
	return runWithArgs(os.Args[1:])
}

func runWithArgs(args []string) int {
	f, positionalArgs, err := cli.Parse(args)
	if err != nil {
		fmt.Fprintf(color.Error, "Error: %v\n", err)
		return constants.ExitError
	}

	if exitCode, handled := handleHelpVersion(f); handled {
		return exitCode
	}

	f.ApplyAllFlag()

	return processInputTokens(f, positionalArgs)
}

func handleHelpVersion(f *cli.Flags) (int, bool) {
	if f.ShowHelp {
		cli.PrintUsage()
		return constants.ExitSuccess, true
	}

	if f.ShowVersion {
		printVersion(f)
		return constants.ExitSuccess, true
	}

	return constants.ExitSuccess, false
}

func processInputTokens(f *cli.Flags, args []string) int {
	argCount := len(args)

	if argCount == 0 {
		return processFromStdin(f, false)
	}

	if argCount == 1 && args[0] == "-" {
		return processFromStdin(f, true)
	}

	for _, token := range args {
		token = parser.NormalizeTokenString(token, f.Strict)
		exitCode := processToken(token, f)
		if exitCode != constants.ExitSuccess {
			return exitCode
		}
	}

	return constants.ExitSuccess
}

func printVersion(f *cli.Flags) {
	fmt.Printf("jwtdebug version %s\n", cli.Version)
	if f.Verbose || cli.Commit != "unknown" {
		fmt.Printf("  commit:     %s\n", cli.Commit)
		fmt.Printf("  built:      %s\n", cli.BuildDate)
	}
}

func processToken(token string, f *cli.Flags) int {
	parsed, err := parser.ParseToken(token)
	if err != nil {
		fmt.Fprintf(color.Error, "Error: %v\n", err)
		return constants.ExitInvalidToken
	}

	if f.RawClaims {
		data, err := json.MarshalIndent(parsed.Claims, "", "  ")
		if err != nil {
			fmt.Fprintf(color.Error, "Error: failed to encode claims as JSON: %v\n", err)
			return constants.ExitError
		}
		fmt.Println(string(data))
		return constants.ExitSuccess
	}

	if !f.VerifySignature {
		printer.PrintUnverifiedNotice(f.Quiet)
	}

	if f.Header {
		printer.PrintHeader(parsed.Token)
	}

	if f.Claims {
		printer.PrintClaims(parsed.Token)
	}

	if f.Signature {
		printer.PrintSignature(parsed.Parts[2])
	}

	if f.Expiration {
		printer.CheckExpiration(parsed.Token)
	}

	if f.VerifySignature {
		if err := verification.VerifyTokenSignature(token, f.KeyFile, f.IgnoreExpiration); err != nil {
			printer.PrintVerificationFailure(err)
			return constants.ExitVerificationFail
		}
		printer.PrintVerificationSuccess()
	}

	return constants.ExitSuccess
}

func isTerminal() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func printUsageHint() {
	fmt.Fprintln(color.Error, "Error: no token provided")
	fmt.Fprintln(color.Error, "")
	fmt.Fprintln(color.Error, "Usage: jwtdebug [options] <token>")
	fmt.Fprintln(color.Error, "       jwtdebug [options] -           # read from stdin")
	fmt.Fprintln(color.Error, "       command | jwtdebug [options]   # read from pipe")
	fmt.Fprintln(color.Error, "")
	fmt.Fprintln(color.Error, "Run 'jwtdebug --help' for more information.")
}

func processFromStdin(f *cli.Flags, explicit bool) int {
	if isTerminal() {
		if !explicit {
			printUsageHint()
			return constants.ExitError
		}
		if !f.Quiet {
			fmt.Fprintln(color.Error, "Reading token from stdin... (press Ctrl+D when done)")
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	hasToken := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = parser.NormalizeTokenString(line, f.Strict)
		if line == "" {
			continue
		}
		hasToken = true
		if exitCode := processToken(line, f); exitCode != constants.ExitSuccess {
			return exitCode
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(color.Error, "Error: failed to read stdin: %v\n", err)
		return constants.ExitError
	}

	if !hasToken {
		fmt.Fprintln(color.Error, "Error: no token provided on stdin")
		return constants.ExitError
	}

	return constants.ExitSuccess
}
