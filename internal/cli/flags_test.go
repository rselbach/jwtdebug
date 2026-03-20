package cli

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
)

func resetFlags() *Flags {
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	return &Flags{}
}

func TestValidateFormat(t *testing.T) {
	tests := map[string]struct {
		input   string
		wantErr bool
	}{
		"pretty": {input: "pretty", wantErr: false},
		"json":   {input: "json", wantErr: false},
		"raw":    {input: "raw", wantErr: false},
		"xml":    {input: "xml", wantErr: true},
		"yaml":   {input: "yaml", wantErr: true},
		"empty":  {input: "", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			err := validateFormat(tc.input)
			if tc.wantErr {
				r.Error(err)
				r.Contains(err.Error(), "invalid format")
			} else {
				r.NoError(err)
			}
		})
	}
}

func TestInitFlags(t *testing.T) {
	r := require.New(t)
	f := resetFlags()
	InitFlags(f)

	// Use -format (deprecated alias) to verify it still works and sets explicit flag
	err := flag.CommandLine.Parse([]string{"-header", "-format", "json", "-all"})
	r.NoError(err)

	ex := &Explicit{}
	r.NoError(f.CheckExplicitFlags(ex))

	r.True(f.WithHeader)
	r.True(ex.Header)
	r.Equal("json", f.OutputFormat)
	r.True(ex.Format)
	r.True(f.ShowAll)
}

func TestApplyAllFlag(t *testing.T) {
	t.Run("all flag enables everything", func(t *testing.T) {
		r := require.New(t)
		f := resetFlags()
		f.ShowAll = true
		f.ApplyAllFlag()

		r.True(f.WithHeader)
		r.True(f.WithClaims)
		r.True(f.WithSignature)
		r.True(f.ShowExpiration)
	})

	t.Run("without all flag nothing changes", func(t *testing.T) {
		r := require.New(t)
		f := resetFlags()
		f.ShowAll = false
		f.ApplyAllFlag()

		r.False(f.WithHeader)
		r.False(f.WithClaims)
		r.False(f.WithSignature)
		r.False(f.ShowExpiration)
	})
}

func TestFlagPrecedence(t *testing.T) {
	r := require.New(t)
	f := resetFlags()
	InitFlags(f)

	err := flag.CommandLine.Parse([]string{"-claims=false"})
	r.NoError(err)

	ex := &Explicit{}
	r.NoError(f.CheckExplicitFlags(ex))

	r.False(f.WithClaims)
	r.True(ex.Claims, "explicit flag should track user override")
}

func TestDeprecatedFlagWarnings(t *testing.T) {
	r := require.New(t)
	f := resetFlags()
	InitFlags(f)

	err := flag.CommandLine.Parse([]string{"-key", "somefile"})
	r.NoError(err)

	ex := &Explicit{}
	r.NoError(f.CheckExplicitFlags(ex))

	r.True(ex.KeyFile)
	r.Equal("somefile", f.KeyFile)
}
