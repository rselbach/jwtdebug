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
		Options: cli.Options{
			Format:           "json",
			Color:            true,
			KeyFile:          "/path/to/key",
			Header:           true,
			Claims:           true,
			Signature:        true,
			Expiration:       true,
			DecodeSignature:  true,
			IgnoreExpiration: false,
		},
	}

	err = SaveConfig(testConfig, configPath)
	r.NoError(err, "Should save config without error")

	loadedConfig, err := LoadConfig(configPath)
	r.NoError(err, "Should load config without error")

	r.Equal(testConfig.Format, loadedConfig.Format)
	r.Equal(testConfig.Color, loadedConfig.Color)
	r.Equal(testConfig.KeyFile, loadedConfig.KeyFile)
	r.Equal(testConfig.Header, loadedConfig.Header)
	r.Equal(testConfig.Claims, loadedConfig.Claims)
	r.Equal(testConfig.Signature, loadedConfig.Signature)
	r.Equal(testConfig.Expiration, loadedConfig.Expiration)
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
		Options: cli.Options{
			Format:           "json",
			Color:            false,
			KeyFile:          "/path/to/key",
			Header:           true,
			Claims:           false,
			Signature:        true,
			Expiration:       true,
			DecodeSignature:  true,
			IgnoreExpiration: false,
		},
	}

	f := &cli.Flags{}
	ex := &cli.Explicit{}
	ApplyConfig(testConfig, f, ex)

	r.Equal("json", f.Format)
	r.False(f.Color)
	r.Equal("/path/to/key", f.KeyFile)
}
