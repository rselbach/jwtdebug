package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/completions"
	"github.com/rselbach/jwtdebug/internal/config"
	"github.com/rselbach/jwtdebug/internal/constants"
	"github.com/rselbach/jwtdebug/internal/parser"
)

func main() {
	os.Exit(run())
}

func run() int {
	cli.InitFlags()
	flag.Parse()

	if exitCode, handled := handleHelpVersion(); handled {
		return exitCode
	}

	if exitCode, handled := handleCompletion(); handled {
		return exitCode
	}

	cfg, exitCode := loadConfig()
	if exitCode != constants.ExitSuccess {
		return exitCode
	}

	cli.ApplyNoColor()

	color.NoColor = !cli.OutputColor

	cli.ApplyAllFlag()

	if exitCode, handled := handleSaveConfig(cfg); handled {
		return exitCode
	}

	return processInputTokens()
}

func handleHelpVersion() (int, bool) {
	if cli.ShowHelp {
		cli.PrintUsage()
		return constants.ExitSuccess, true
	}

	if cli.ShowVersion {
		printVersion()
		return constants.ExitSuccess, true
	}

	return constants.ExitSuccess, false
}

func handleCompletion() (int, bool) {
	if cli.CompletionShell == "" {
		return constants.ExitSuccess, false
	}

	return generateCompletion(cli.CompletionShell), true
}

func loadConfig() (*config.Config, int) {
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to load config: %v\n", err)
		return nil, constants.ExitConfigError
	}

	config.ApplyConfig(cfg)
	return cfg, constants.ExitSuccess
}

func handleSaveConfig(cfg *config.Config) (int, bool) {
	if !cli.SaveConfig {
		return constants.ExitSuccess, false
	}

	config.UpdateFromCLI(cfg)

	savePath := cli.ConfigFile
	if err := config.SaveConfig(cfg, savePath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to save config: %v\n", err)
		return constants.ExitConfigError, true
	}
	color.Green("Configuration saved successfully.")

	// if no token provided, exit after saving config
	if flag.NArg() == 0 {
		return constants.ExitSuccess, true
	}

	return constants.ExitSuccess, false
}

func processInputTokens() int {
	argCount := flag.NArg()

	// check for explicit stdin marker "-"
	if argCount == 0 {
		return processFromStdin(false)
	}

	if argCount == 1 && flag.Arg(0) == "-" {
		return processFromStdin(true)
	}

	// process tokens provided as arguments
	for _, token := range flag.Args() {
		token = parser.NormalizeTokenString(token)
		exitCode := processToken(token)
		if exitCode != constants.ExitSuccess {
			return exitCode
		}
	}

	return constants.ExitSuccess
}

func printVersion() {
	fmt.Printf("jwtdebug version %s\n", cli.Version)
	if cli.Verbose || cli.Commit != "unknown" {
		fmt.Printf("  commit:     %s\n", cli.Commit)
		fmt.Printf("  built:      %s\n", cli.BuildDate)
	}
}

func generateCompletion(shell string) int {
	switch strings.ToLower(shell) {
	case "bash":
		completions.PrintBash()
	case "zsh":
		completions.PrintZsh()
	case "fish":
		completions.PrintFish()
	default:
		fmt.Fprintf(os.Stderr, "Error: unsupported shell %q (supported: bash, zsh, fish)\n", shell)
		return constants.ExitError
	}
	return constants.ExitSuccess
}

func processToken(token string) int {
	result := parser.ProcessToken(token)
	if result.Err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", result.Err)
		return result.ExitCode
	}
	return result.ExitCode
}

func processFromStdin(explicit bool) int {
	// check if stdin has data
	stat, err := os.Stdin.Stat()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to stat stdin: %v\n", err)
		return constants.ExitError
	}

	// if stdin is a terminal and not explicitly requested, show hint
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		if explicit {
			// explicit "-" argument, wait for input
			if !cli.Quiet {
				fmt.Fprintln(os.Stderr, "Reading token from stdin... (press Ctrl+D when done)")
			}
		}
		if !explicit {
			fmt.Fprintln(os.Stderr, "Error: no token provided")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Usage: jwtdebug [options] <token>")
			fmt.Fprintln(os.Stderr, "       jwtdebug [options] -           # read from stdin")
			fmt.Fprintln(os.Stderr, "       command | jwtdebug [options]   # read from pipe")
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Run 'jwtdebug --help' for more information.")
			return constants.ExitError
		}
	}

	scanner := bufio.NewScanner(os.Stdin)
	// allow reasonable JWT inputs (up to 1MB to prevent DoS)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	hasToken := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = parser.NormalizeTokenString(line)
		if line == "" {
			continue
		}
		hasToken = true
		exitCode := processToken(line)
		if exitCode != constants.ExitSuccess {
			return exitCode
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to read stdin: %v\n", err)
		return constants.ExitError
	}

	if !hasToken {
		fmt.Fprintln(os.Stderr, "Error: no token provided on stdin")
		return constants.ExitError
	}

	return constants.ExitSuccess
}
