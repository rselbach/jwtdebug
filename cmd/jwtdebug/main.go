package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/config"
	"github.com/rselbach/jwtdebug/internal/parser"
)

func main() {
	// initialize flags
	cli.InitFlags()
	flag.Parse()

	// show version and exit if requested
	if cli.ShowVersion {
		fmt.Printf("jwtdebug version: %s\n", cli.Version)
		return
	}

	// load configuration from file
	cfg, err := config.LoadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to load config: %v\n", err)
		os.Exit(-1)
	}
	// apply configuration (only for options not explicitly set via CLI)
	config.ApplyConfig(cfg)

	// enable all output options if -all flag is set
	cli.EnableAllOutputs()

	// handle save config request
	if cli.SaveConfig {
		// update config with current settings
		cfg.DefaultFormat = cli.OutputFormat
		cfg.ColorEnabled = cli.OutputColor
		cfg.DefaultKeyFile = cli.KeyFile
		cfg.ShowHeader = cli.WithHeader
		cfg.ShowClaims = cli.WithClaims
		cfg.ShowSignature = cli.WithSignature
		cfg.ShowExpiration = cli.ShowExpiration
		cfg.DecodeSignature = cli.DecodeBase64
		cfg.IgnoreExpiration = cli.IgnoreExpiration

		// save config
		if err := config.SaveConfig(cfg, ""); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to save config: %v\n", err)
			os.Exit(1)
		}
		color.Green("Configuration saved successfully.")

		// if no token provided, exit after saving config
		if flag.NArg() == 0 {
			return
		}
	}

	// process tokens from arguments or stdin
	if flag.NArg() == 0 {
		if err := processFromStdin(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// process tokens provided as arguments
	for _, token := range flag.Args() {
		// skip Bearer prefix if present
		token = strings.TrimPrefix(strings.TrimPrefix(token, "Bearer "), "bearer ")

		if err := parser.ProcessToken(token); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}

func processFromStdin() error {
	// check if stdin has data
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		return fmt.Errorf("no token provided and no data on stdin")
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()
		// skip Bearer prefix if present
		line = strings.TrimPrefix(strings.TrimPrefix(line, "Bearer "), "bearer ")
		if line == "" {
			continue
		}
		if err := parser.ProcessToken(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}
