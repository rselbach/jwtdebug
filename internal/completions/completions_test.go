package completions

import (
	"testing"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/stretchr/testify/require"
)

func TestBashCompletionContainsAllFlags(t *testing.T) {
	r := require.New(t)
	script := Bash()

	for _, spec := range cli.AllOptionSpecs() {
		if spec.Deprecated != "" {
			continue
		}
		for _, name := range spec.Names {
			if len(name) == 1 {
				r.Contains(script, "-"+name, "bash completion missing flag: -%s", name)
			} else {
				r.Contains(script, "--"+name, "bash completion missing flag: --%s", name)
			}
		}
	}
}

func TestZshCompletionContainsAllFlags(t *testing.T) {
	r := require.New(t)
	script := Zsh()

	for _, spec := range cli.AllOptionSpecs() {
		if spec.Deprecated != "" {
			continue
		}
		for _, name := range spec.Names {
			if len(name) == 1 {
				r.Contains(script, "-"+name, "zsh completion missing flag: -%s", name)
			} else {
				r.Contains(script, "--"+name, "zsh completion missing flag: --%s", name)
			}
		}
	}
}

func TestFishCompletionContainsAllFlags(t *testing.T) {
	r := require.New(t)
	script := Fish()

	for _, spec := range cli.AllOptionSpecs() {
		if spec.Deprecated != "" {
			continue
		}
		for _, name := range spec.Names {
			if len(name) == 1 {
				r.Contains(script, "-s "+name, "fish completion missing flag: -%s", name)
			} else {
				r.Contains(script, "-l "+name, "fish completion missing flag: --%s", name)
			}
		}
	}
}

func TestCompletionScriptsNotContainsDeprecatedFlags(t *testing.T) {
	r := require.New(t)

	for _, spec := range cli.AllOptionSpecs() {
		if spec.Deprecated == "" {
			continue
		}
		for _, script := range []string{Bash(), Zsh(), Fish()} {
			for _, name := range spec.Names {
				var flagRef string
				if len(name) == 1 {
					flagRef = "-" + name
				} else {
					flagRef = "--" + name
				}
				// Look for the flag followed by a word boundary (space, quote, or paren)
				r.NotContains(script, flagRef+" ", "completion script should not list deprecated flag: %s", flagRef)
			}
		}
	}
}
