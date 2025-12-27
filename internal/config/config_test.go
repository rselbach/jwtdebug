package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rselbach/jwtdebug/internal/cli"
	"github.com/stretchr/testify/require"
)

func TestLoadSaveConfig(t *testing.T) {
	r := require.New(t)

	// Create a temporary directory for config file
	tempDir, err := os.MkdirTemp("", "jwtdebug-test")
	r.NoError(err)
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")

	// Test config
	testConfig := &Config{
		DefaultFormat:    "json",
		ColorEnabled:     true,
		DefaultKeyFile:   "/path/to/key",
		ShowHeader:       true,
		ShowClaims:       true,
		ShowSignature:    true,
		ShowExpiration:   true,
		DecodeSignature:  true,
		IgnoreExpiration: false,
	}

	// Save config
	err = SaveConfig(testConfig, configPath)
	r.NoError(err, "Should save config without error")

	// Save original CLI config file
	originalConfigFile := cli.ConfigFile
	cli.ConfigFile = configPath
	t.Cleanup(func() { cli.ConfigFile = originalConfigFile })

	// Load config
	loadedConfig, err := LoadConfig()
	r.NoError(err, "Should load config without error")

	// Verify config values
	r.Equal(testConfig.DefaultFormat, loadedConfig.DefaultFormat)
	r.Equal(testConfig.ColorEnabled, loadedConfig.ColorEnabled)
	r.Equal(testConfig.DefaultKeyFile, loadedConfig.DefaultKeyFile)
	r.Equal(testConfig.ShowHeader, loadedConfig.ShowHeader)
	r.Equal(testConfig.ShowClaims, loadedConfig.ShowClaims)
	r.Equal(testConfig.ShowSignature, loadedConfig.ShowSignature)
	r.Equal(testConfig.ShowExpiration, loadedConfig.ShowExpiration)
	r.Equal(testConfig.DecodeSignature, loadedConfig.DecodeSignature)
	r.Equal(testConfig.IgnoreExpiration, loadedConfig.IgnoreExpiration)
}

func TestLoadConfigErrors(t *testing.T) {
	r := require.New(t)

	// Save original CLI config file
	originalConfigFile := cli.ConfigFile
	cli.ConfigFile = "/path/to/non-existent-config.json"
	t.Cleanup(func() { cli.ConfigFile = originalConfigFile })

	// Test loading from non-existent file
	_, err := LoadConfig()
	r.Error(err, "Should return error for non-existent config file")
}

func TestApplyConfig(t *testing.T) {
	r := require.New(t)

	testConfig := &Config{
		DefaultFormat:    "json",
		ColorEnabled:     false,
		DefaultKeyFile:   "/path/to/key",
		ShowHeader:       true,
		ShowClaims:       false,
		ShowSignature:    true,
		ShowExpiration:   true,
		DecodeSignature:  true,
		IgnoreExpiration: false,
	}

	// Mock some CLI flags
	cli.FormatExplicit = false
	cli.ColorExplicit = false
	cli.KeyFileExplicit = false
	cli.HeaderExplicit = false
	cli.ClaimsExplicit = false
	cli.SignatureExplicit = false
	cli.ExpirationExplicit = false
	cli.DecodeBase64Explicit = false
	cli.IgnoreExpirationExplicit = false

	// Mock existing CLI flags
	ApplyConfig(testConfig)

	// Add assertions to verify config application
	r.Equal("json", cli.OutputFormat)
	r.False(cli.OutputColor)
	r.Equal("/path/to/key", cli.KeyFile)
}
