package jwtdebug

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

var (
	version   string
	commit    = "unknown"
	buildDate = "unknown"
)

// Run executes jwtdebug with the supplied process streams and returns its exit code.
func Run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	ignoreSIGPIPE()

	out := newOutput(stdout, stderr)
	exitCode := run(args, stdin, isTerminal(stdin), out)
	outputErr := out.finish()
	if outputErr != nil && !isOnlyBrokenPipe(outputErr) {
		_, _ = fmt.Fprintf(stderr, "Error: failed to write output: %v\n", outputErr)
	}

	return finalExitCode(exitCode, outputErr)
}

func isBrokenPipe(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) || isPlatformBrokenPipe(err)
}

func isOnlyBrokenPipe(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errors := joined.Unwrap()
		if len(errors) == 0 {
			return false
		}
		for _, child := range errors {
			if !isOnlyBrokenPipe(child) {
				return false
			}
		}
		return true
	}
	return isBrokenPipe(err)
}

func resolvedVersion() string {
	if version != "" {
		return strings.TrimPrefix(version, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return "devel"
}

func finalExitCode(exitCode int, outputErr error) int {
	switch {
	case outputErr == nil:
		return exitCode
	case isOnlyBrokenPipe(outputErr):
		return exitSuccess
	default:
		return exitError
	}
}
