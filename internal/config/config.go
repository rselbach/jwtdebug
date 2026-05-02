package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/rselbach/jwtdebug/internal/constants"
)

// Config represents the application configuration
type Config struct {
	cli.Options
}

// DefaultConfig returns the default configuration values
func DefaultConfig() *Config {
	return &Config{
		Options: cli.Options{
			Format:           "pretty",
			Color:            true,
			Claims:           true,
			Header:           false,
			Signature:        false,
			Expiration:       false,
			DecodeSignature:  false,
			IgnoreExpiration: false,
		},
	}
}

// MarshalJSON preserves the original config file field names for backward compatibility.
func (c Config) MarshalJSON() ([]byte, error) {
	type proxy struct {
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
	return json.Marshal(proxy{
		DefaultFormat:    c.Options.Format,
		ColorEnabled:     c.Options.Color,
		DefaultKeyFile:   c.Options.KeyFile,
		ShowHeader:       c.Options.Header,
		ShowClaims:       c.Options.Claims,
		ShowSignature:    c.Options.Signature,
		ShowExpiration:   c.Options.Expiration,
		DecodeSignature:  c.Options.DecodeSignature,
		IgnoreExpiration: c.Options.IgnoreExpiration,
	})
}

// UnmarshalJSON reads the original config file field names into the shared Options struct.
func (c *Config) UnmarshalJSON(data []byte) error {
	type proxy struct {
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
	var p proxy
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	c.Options = cli.Options{
		Format:           p.DefaultFormat,
		Color:            p.ColorEnabled,
		KeyFile:          p.DefaultKeyFile,
		Header:           p.ShowHeader,
		Claims:           p.ShowClaims,
		Signature:        p.ShowSignature,
		Expiration:       p.ShowExpiration,
		DecodeSignature:  p.DecodeSignature,
		IgnoreExpiration: p.IgnoreExpiration,
	}
	return nil
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

	if config.Format != "" && !cli.ValidFormats[config.Format] {
		return nil, fmt.Errorf("invalid format %q in config, must be one of: pretty, json, raw", config.Format)
	}

	return config, nil
}

func applyIfNotExplicit[T any](explicit bool, field *T, configVal T) {
	if !explicit {
		*field = configVal
	}
}

// ApplyConfig applies the configuration to CLI flags if they weren't explicitly set
func ApplyConfig(config *Config, f *cli.Flags, ex *cli.Explicit) {
	applyIfNotExplicit(ex.Format, &f.Format, config.Format)
	applyIfNotExplicit(ex.Color, &f.Color, config.Color)
	applyIfNotExplicit(ex.KeyFile, &f.KeyFile, config.KeyFile)
	applyIfNotExplicit(ex.Header, &f.Header, config.Header)
	applyIfNotExplicit(ex.Claims, &f.Claims, config.Claims)
	applyIfNotExplicit(ex.Signature, &f.Signature, config.Signature)
	applyIfNotExplicit(ex.Expiration, &f.Expiration, config.Expiration)
	applyIfNotExplicit(ex.DecodeSignature, &f.DecodeSignature, config.DecodeSignature)
	applyIfNotExplicit(ex.IgnoreExpiration, &f.IgnoreExpiration, config.IgnoreExpiration)
}

// UpdateFromCLI updates the config with CLI values.
func UpdateFromCLI(config *Config, f *cli.Flags) {
	config.Options = f.Options
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
