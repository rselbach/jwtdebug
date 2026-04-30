package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/constants"
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
		filepath.Join(home, ".jwtdebug.json"),
		filepath.Join(home, ".config", "jwtdebug.json"),
		filepath.Join(home, ".config", "jwtdebug", "config.json"),
	}
}

// LoadConfig loads configuration from a file
func LoadConfig(configFile string) (*Config, error) {
	config := DefaultConfig()

	var configPath string
	for _, path := range defaultConfigPaths() {
		if _, err := os.Stat(path); err == nil {
			configPath = path
			break
		}
	}

	if configFile != "" {
		configPath = configFile
	}

	if configPath == "" {
		return config, nil
	}

	stat, err := os.Stat(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat config file: %w", err)
	}
	if stat.Size() > constants.MaxFileSizeBytes {
		return nil, fmt.Errorf("config file too large (max %d bytes)", constants.MaxFileSizeBytes)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := json.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if config.DefaultFormat != "" && !cli.ValidFormats[config.DefaultFormat] {
		return nil, fmt.Errorf("invalid format %q in config, must be one of: pretty, json, raw", config.DefaultFormat)
	}

	return config, nil
}

// ApplyConfig applies the configuration to CLI flags if they weren't explicitly set
func ApplyConfig(config *Config, f *cli.Flags, ex *cli.Explicit) {
	if !ex.Format {
		f.OutputFormat = config.DefaultFormat
	}
	if !ex.Color {
		f.OutputColor = config.ColorEnabled
	}
	if !ex.KeyFile && f.KeyFile == "" {
		f.KeyFile = config.DefaultKeyFile
	}
	if !ex.Header {
		f.WithHeader = config.ShowHeader
	}
	if !ex.Claims {
		f.WithClaims = config.ShowClaims
	}
	if !ex.Signature {
		f.WithSignature = config.ShowSignature
	}
	if !ex.Expiration {
		f.ShowExpiration = config.ShowExpiration
	}
	if !ex.DecodeBase64 {
		f.DecodeBase64 = config.DecodeSignature
	}
	if !ex.IgnoreExpiration {
		if config.IgnoreExpiration {
			fmt.Fprintln(color.Error, "Warning: ignoring token expiration (from config). Use --ignore-expiration to confirm.")
		}
		f.IgnoreExpiration = config.IgnoreExpiration
	}
}

// UpdateFromCLI updates the config with CLI values.
func UpdateFromCLI(config *Config, f *cli.Flags) {
	config.DefaultFormat = f.OutputFormat
	config.ColorEnabled = f.OutputColor
	config.DefaultKeyFile = f.KeyFile
	config.ShowHeader = f.WithHeader
	config.ShowClaims = f.WithClaims
	config.ShowSignature = f.WithSignature
	config.ShowExpiration = f.ShowExpiration
	config.DecodeSignature = f.DecodeBase64
	config.IgnoreExpiration = f.IgnoreExpiration
}

// SaveConfig saves the current configuration to a file
func SaveConfig(config *Config, path string) error {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		path = filepath.Join(home, ".jwtdebug.json")
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
