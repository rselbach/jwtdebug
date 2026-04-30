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
	f := &cli.Flags{}
	ex := &cli.Explicit{}

	cli.InitFlags(f)
	flag.Parse()

	if err := f.CheckExplicitFlags(ex); err != nil {
		fmt.Fprintf(color.Error, "Error: %v\n", err)
		return constants.ExitError
	}

	if exitCode, handled := handleHelpVersion(f); handled {
		return exitCode
	}

	if exitCode, handled := handleCompletion(f); handled {
		return exitCode
	}

	cfg, exitCode := loadConfig(f, ex)
	if exitCode != constants.ExitSuccess {
		return exitCode
	}

	f.ApplyColorSettings()

	f.ApplyAllFlag()

	if exitCode, handled := handleSaveConfig(cfg, f); handled {
		return exitCode
	}

	return processInputTokens(f)
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

func handleCompletion(f *cli.Flags) (int, bool) {
	if f.CompletionShell == "" {
		return constants.ExitSuccess, false
	}

	return generateCompletion(f.CompletionShell), true
}

func loadConfig(f *cli.Flags, ex *cli.Explicit) (*config.Config, int) {
	cfg, err := config.LoadConfig(f.ConfigFile)
	if err != nil {
		fmt.Fprintf(color.Error, "Error: failed to load config: %v\n", err)
		return nil, constants.ExitConfigError
	}

	config.ApplyConfig(cfg, f, ex)
	return cfg, constants.ExitSuccess
}

func handleSaveConfig(cfg *config.Config, f *cli.Flags) (int, bool) {
	if !f.SaveConfig {
		return constants.ExitSuccess, false
	}

	config.UpdateFromCLI(cfg, f)

	savePath := f.ConfigFile
	if err := config.SaveConfig(cfg, savePath); err != nil {
		fmt.Fprintf(color.Error, "Error: Failed to save config: %v\n", err)
		return constants.ExitConfigError, true
	}
	color.Green("Configuration saved successfully.")

	if flag.NArg() == 0 {
		return constants.ExitSuccess, true
	}

	return constants.ExitSuccess, false
}

func processInputTokens(f *cli.Flags) int {
	argCount := flag.NArg()

	if argCount == 0 {
		return processFromStdin(f, false)
	}

	if argCount == 1 && flag.Arg(0) == "-" {
		return processFromStdin(f, true)
	}

	for _, token := range flag.Args() {
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

func generateCompletion(shell string) int {
	switch strings.ToLower(shell) {
	case "bash":
		completions.PrintBash()
	case "zsh":
		completions.PrintZsh()
	case "fish":
		completions.PrintFish()
	default:
		fmt.Fprintf(color.Error, "Error: unsupported shell %q (supported: bash, zsh, fish)\n", shell)
		return constants.ExitError
	}
	return constants.ExitSuccess
}

func processToken(token string, f *cli.Flags) int {
	result := parser.ProcessToken(token, f)
	if result.Err != nil {
		fmt.Fprintf(color.Error, "Error: %v\n", result.Err)
		return result.ExitCode
	}
	return result.ExitCode
}

func processFromStdin(f *cli.Flags, explicit bool) int {
	stat, err := os.Stdin.Stat()
	if err != nil {
		fmt.Fprintf(color.Error, "Error: failed to stat stdin: %v\n", err)
		return constants.ExitError
	}

	if (stat.Mode() & os.ModeCharDevice) != 0 {
		if explicit {
			if !f.Quiet {
				fmt.Fprintln(color.Error, "Reading token from stdin... (press Ctrl+D when done)")
			}
		}
		if !explicit {
			fmt.Fprintln(color.Error, "Error: no token provided")
			fmt.Fprintln(color.Error, "")
			fmt.Fprintln(color.Error, "Usage: jwtdebug [options] <token>")
			fmt.Fprintln(color.Error, "       jwtdebug [options] -           # read from stdin")
			fmt.Fprintln(color.Error, "       command | jwtdebug [options]   # read from pipe")
			fmt.Fprintln(color.Error, "")
			fmt.Fprintln(color.Error, "Run 'jwtdebug --help' for more information.")
			return constants.ExitError
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
		exitCode := processToken(line, f)
		if exitCode != constants.ExitSuccess {
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
