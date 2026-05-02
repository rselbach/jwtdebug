package cli

import (
	"flag"
	"testing"

	"github.com/stretchr/testify/require"
)

func newFlagSet(t *testing.T) *flag.FlagSet {
	t.Helper()
	return flag.NewFlagSet("test", flag.ContinueOnError)
}

func TestInitFlags(t *testing.T) {
	r := require.New(t)
	f := &Flags{}
	fs := newFlagSet(t)
	InitFlags(fs, f)

	err := fs.Parse([]string{"-header", "-all"})
	r.NoError(err)

	r.NoError(checkExplicitFlags(fs, f))

	r.True(f.Header)
	r.True(f.ShowAll)
}

func TestApplyAllFlag(t *testing.T) {
	t.Run("all flag enables everything", func(t *testing.T) {
		r := require.New(t)
		f := &Flags{}
		f.ShowAll = true
		f.ApplyAllFlag()

		r.True(f.Header)
		r.True(f.Claims)
		r.True(f.Signature)
		r.True(f.Expiration)
	})

	t.Run("without all flag nothing changes", func(t *testing.T) {
		r := require.New(t)
		f := &Flags{}
		f.ShowAll = false
		f.ApplyAllFlag()

		r.False(f.Header)
		r.False(f.Claims)
		r.False(f.Signature)
		r.False(f.Expiration)
	})
}

func TestFlagPrecedence(t *testing.T) {
	r := require.New(t)
	f := &Flags{}
	fs := newFlagSet(t)
	InitFlags(fs, f)

	err := fs.Parse([]string{"-claims=false"})
	r.NoError(err)

	r.NoError(checkExplicitFlags(fs, f))

	r.False(f.Claims)
}

func TestDeprecatedFlagWarnings(t *testing.T) {
	t.Run("deprecated alias sets field", func(t *testing.T) {
		r := require.New(t)
		f := &Flags{}
		fs := newFlagSet(t)
		InitFlags(fs, f)

		err := fs.Parse([]string{"-key", "somefile"})
		r.NoError(err)

		r.NoError(checkExplicitFlags(fs, f))

		r.Equal("somefile", f.KeyFile)
	})

	t.Run("deprecated aliases have replacement hints in specs", func(t *testing.T) {
		r := require.New(t)

		findSpec := func(name string) *OptionSpec {
			for _, spec := range AllOptionSpecs() {
				for _, n := range spec.Names {
					if n == name {
						return &spec
					}
				}
			}
			return nil
		}

		r.Equal("--key-file", findSpec("key").Deprecated)
		r.Equal("--expiration", findSpec("expiry").Deprecated)
		r.Equal("--ignore-expiration", findSpec("ignore-exp").Deprecated)
	})

	t.Run("non-deprecated flags have empty replacement", func(t *testing.T) {
		r := require.New(t)

		findSpec := func(name string) *OptionSpec {
			for _, spec := range AllOptionSpecs() {
				for _, n := range spec.Names {
					if n == name {
						return &spec
					}
				}
			}
			return nil
		}

		r.Empty(findSpec("header").Deprecated)
		r.Empty(findSpec("claims").Deprecated)
		r.Empty(findSpec("key-file").Deprecated)
		r.Empty(findSpec("verify").Deprecated)
	})
}
