package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rselbach/jwtdebug/internal/cli"
)

// Config represents the application configuration
type Config struct {
	DefaultFormat    string `json:"defaultFormat"`
	ColorEnabled     bool   `json:"colorEnabled"`
	DefaultKeyFile   string `json:"defaultKeyFile"`
	ShowHeader       bool   `json:"showHeader"`
	ShowClaims       bool   `json:"showClaims"`
	ShowSignature    bool   `json:"showSignature"`
	ShowExpiration   bool   `json:"showExpiration"`
	DecodeSignature  bool   `json:"decodeSignature"`
	IgnoreExpiration bool   `json:"ignoreExpiration"`
}

// DefaultConfig returns the default configuration values
func DefaultConfig() *Config {
	return &Config{
		DefaultFormat:    "pretty",
		ColorEnabled:     true,
		ShowClaims:       true,
		ShowHeader:       false,
		ShowSignature:    false,
		ShowExpiration:   false,
		DecodeSignature:  false,
		IgnoreExpiration: false,
	}
}

// defaultConfigPaths returns the default locations to look for config files
func defaultConfigPaths() []string {
	// Get user's home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return []string{}
	}

	// Configuration file paths in order of precedence
	return []string{
		// Removed current directory lookup to avoid untrusted config precedence
		filepath.Join(home, ".jwtdebug.json"),                     // user's home directory
		filepath.Join(home, ".config", "jwtdebug.json"),           // XDG config directory
		filepath.Join(home, ".config", "jwtdebug", "config.json"), // XDG config directory
	}
}

// LoadConfig loads configuration from a file
func LoadConfig() (*Config, error) {
	// Default configuration
	config := DefaultConfig()

	// Look for config file in default locations
	var configPath string
	for _, path := range defaultConfigPaths() {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	// If explicit config path provided via CLI
	if cli.ConfigFile != "" {
		configPath = cli.ConfigFile
	}

	// If no config file found or provided
	if configPath == "" {
		return config, nil
	}

	// Read and parse config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	return config, nil
}

// ApplyConfig applies the configuration to CLI flags if they weren't explicitly set
func ApplyConfig(config *Config) {
	// Only set values from config if not explicitly set via command line
	if !cli.FormatExplicit {
		cli.OutputFormat = config.DefaultFormat
	}

	if !cli.ColorExplicit {
		cli.OutputColor = config.ColorEnabled
	}

	if !cli.KeyFileExplicit && cli.KeyFile == "" {
		cli.KeyFile = config.DefaultKeyFile
	}

	if !cli.HeaderExplicit {
		cli.WithHeader = config.ShowHeader
	}

	if !cli.ClaimsExplicit {
		cli.WithClaims = config.ShowClaims
	}

	if !cli.SignatureExplicit {
		cli.WithSignature = config.ShowSignature
	}

	if !cli.ExpirationExplicit {
		cli.ShowExpiration = config.ShowExpiration
	}

	if !cli.DecodeBase64Explicit {
		cli.DecodeBase64 = config.DecodeSignature
	}

	if !cli.IgnoreExpirationExplicit {
		cli.IgnoreExpiration = config.IgnoreExpiration
	}
}

// SaveConfig saves the current configuration to a file
func SaveConfig(config *Config, path string) error {
	// If no path specified, use default
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, ".jwtdebug.json")
	}

	// Serialize config
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	// Write to file
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
