package completions

import "github.com/rselbach/jwtdebug/internal/cli"

// Bash returns the bash completion script.
func Bash() string {
	return cli.GenerateBashCompletion()
}

// Zsh returns the zsh completion script.
func Zsh() string {
	return cli.GenerateZshCompletion()
}

// Fish returns the fish completion script.
func Fish() string {
	return cli.GenerateFishCompletion()
}
