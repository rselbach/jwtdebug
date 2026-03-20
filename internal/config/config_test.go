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

	tempDir, err := os.MkdirTemp("", "jwtdebug-test")
	r.NoError(err)
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")

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

	err = SaveConfig(testConfig, configPath)
	r.NoError(err, "Should save config without error")

	loadedConfig, err := LoadConfig(configPath)
	r.NoError(err, "Should load config without error")

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

	_, err := LoadConfig("/path/to/non-existent-config.json")
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

	f := &cli.Flags{}
	ex := &cli.Explicit{}
	ApplyConfig(testConfig, f, ex)

	r.Equal("json", f.OutputFormat)
	r.False(f.OutputColor)
	r.Equal("/path/to/key", f.KeyFile)
}
