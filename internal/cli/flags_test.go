package cli

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
)

func resetFlags() {
	flag.CommandLine = flag.NewFlagSet("test", flag.ContinueOnError)
	WithHeader = false
	WithClaims = false
	WithSignature = false
	VerifySignature = false
	KeyFile = ""
	OutputFormat = ""
	OutputColor = false
	ShowExpiration = false
	ShowAll = false
	DecodeBase64 = false
	IgnoreExpiration = false
	ConfigFile = ""
	SaveConfig = false
	ShowVersion = false
	HeaderExplicit = false
	ClaimsExplicit = false
	SignatureExplicit = false
	KeyFileExplicit = false
	FormatExplicit = false
	ColorExplicit = false
	ExpirationExplicit = false
	DecodeBase64Explicit = false
	IgnoreExpirationExplicit = false
}

func TestBoolFlag(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    bool
		wantErr bool
	}{
		"true":    {input: "true", want: true},
		"false":   {input: "false", want: false},
		"1":       {input: "1", want: true},
		"0":       {input: "0", want: false},
		"T":       {input: "T", want: true},
		"F":       {input: "F", want: false},
		"invalid": {input: "maybe", wantErr: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var set, value bool
			f := boolFlag{set: &set, value: &value, defValue: false}

			err := f.Set(tc.input)

			if tc.wantErr {
				r.Error(err)
				return
			}
			r.NoError(err)
			r.True(set, "set flag should be true")
			r.Equal(tc.want, value)
		})
	}
}

func TestBoolFlagString(t *testing.T) {
	r := require.New(t)

	t.Run("nil value returns default", func(t *testing.T) {
		f := boolFlag{defValue: true}
		r.Equal("true", f.String())
	})

	t.Run("non-nil value returns current", func(t *testing.T) {
		val := false
		f := boolFlag{value: &val, defValue: true}
		r.Equal("false", f.String())
	})
}

func TestBoolFlagIsBoolFlag(t *testing.T) {
	r := require.New(t)
	f := boolFlag{}
	r.True(f.IsBoolFlag())
}

func TestStringFlag(t *testing.T) {
	tests := map[string]struct {
		input     string
		validator func(string) error
		want      string
		wantErr   bool
	}{
		"valid format":   {input: "json", validator: validateFormat, want: "json"},
		"invalid format": {input: "xml", validator: validateFormat, wantErr: true},
		"no validator":   {input: "anything", validator: nil, want: "anything"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var set bool
			var value string
			f := stringFlag{set: &set, value: &value, validator: tc.validator}

			err := f.Set(tc.input)

			if tc.wantErr {
				r.Error(err)
				return
			}
			r.NoError(err)
			r.True(set, "set flag should be true")
			r.Equal(tc.want, value)
		})
	}
}

func TestStringFlagString(t *testing.T) {
	r := require.New(t)

	t.Run("nil value returns default", func(t *testing.T) {
		f := stringFlag{defValue: "pretty"}
		r.Equal("pretty", f.String())
	})

	t.Run("non-nil value returns current", func(t *testing.T) {
		val := "json"
		f := stringFlag{value: &val, defValue: "pretty"}
		r.Equal("json", f.String())
	})
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
	resetFlags()
	InitFlags()

	err := flag.CommandLine.Parse([]string{"-header", "-format", "json", "-all"})
	r.NoError(err)

	r.True(WithHeader)
	r.True(HeaderExplicit)
	r.Equal("json", OutputFormat)
	r.True(FormatExplicit)
	r.True(ShowAll)
}

func TestEnableAllOutputs(t *testing.T) {
	r := require.New(t)

	t.Run("all flag enables everything", func(t *testing.T) {
		resetFlags()
		ShowAll = true
		ApplyAllFlag()

		r.True(WithHeader)
		r.True(WithClaims)
		r.True(WithSignature)
		r.True(ShowExpiration)
	})

	t.Run("without all flag nothing changes", func(t *testing.T) {
		resetFlags()
		ShowAll = false
		ApplyAllFlag()

		r.False(WithHeader)
		r.False(WithClaims)
		r.False(WithSignature)
		r.False(ShowExpiration)
	})
}

func TestFlagPrecedence(t *testing.T) {
	r := require.New(t)
	resetFlags()
	InitFlags()

	err := flag.CommandLine.Parse([]string{"-claims=false"})
	r.NoError(err)

	r.False(WithClaims)
	r.True(ClaimsExplicit, "explicit flag should track user override")
}
