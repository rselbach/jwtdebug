package jwtdebug

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
)

const sourceVersion = "1.3.1"

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
	if outputErr != nil && !isBrokenPipe(outputErr) {
		if _, err := fmt.Fprintf(stderr, "Error: failed to write output: %v\n", outputErr); err != nil {
			outputErr = errors.Join(outputErr, err)
		}
	}

	return finalExitCode(exitCode, outputErr)
}

func isBrokenPipe(err error) bool {
	return errors.Is(err, io.ErrClosedPipe) || isPlatformBrokenPipe(err)
}

func resolvedVersion() string {
	if version != "" {
		return strings.TrimPrefix(version, "v")
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return strings.TrimPrefix(info.Main.Version, "v")
	}
	return sourceVersion
}

func finalExitCode(exitCode int, outputErr error) int {
	switch {
	case outputErr == nil:
		return exitCode
	case isBrokenPipe(outputErr):
		return exitSuccess
	default:
		return exitError
	}
}
