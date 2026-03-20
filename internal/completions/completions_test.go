package completions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Known CLI flags that should appear in completion scripts.
var knownFlags = []string{
	"--header", "--claims", "--signature", "--verify", "--key-file",
	"--output", "--color", "--no-color", "--expiration", "--all",
	"--decode-signature", "--ignore-expiration", "--config", "--save-config",
	"--version", "--quiet", "--verbose", "--raw-claims", "--help",
	"--strict",
}

// fishFlags are the long-form flags expected in fish completions (uses -l prefix).
var fishKnownFlags = []string{
	"-l header", "-l claims", "-l signature", "-l verify", "-l key-file",
	"-l output", "-l color", "-l no-color", "-l expiration", "-l all",
	"-l decode-signature", "-l ignore-expiration", "-l config", "-l save-config",
	"-l version", "-l quiet", "-l verbose", "-l raw-claims", "-l help",
	"-l strict",
}

func TestBashCompletionContainsAllFlags(t *testing.T) {
	r := require.New(t)
	script := Bash()

	for _, flag := range knownFlags {
		r.Contains(script, flag, "bash completion missing flag: %s", flag)
	}
}

func TestZshCompletionContainsAllFlags(t *testing.T) {
	r := require.New(t)
	script := Zsh()

	for _, flag := range knownFlags {
		r.Contains(script, flag, "zsh completion missing flag: %s", flag)
	}
}

func TestFishCompletionContainsAllFlags(t *testing.T) {
	r := require.New(t)
	script := Fish()

	for _, flag := range fishKnownFlags {
		r.Contains(script, flag, "fish completion missing flag: %s", flag)
	}
}

func TestCompletionScriptsNotContainsDeprecatedFlags(t *testing.T) {
	r := require.New(t)

	deprecated := []string{"--key ", "--format ", "--expiry ", "--decode-sig ", "--ignore-exp "}

	for _, script := range []string{Bash(), Zsh(), Fish()} {
		for _, dep := range deprecated {
			r.NotContains(script, dep, "completion script should not list deprecated flag: %s", strings.TrimSpace(dep))
		}
	}
}
