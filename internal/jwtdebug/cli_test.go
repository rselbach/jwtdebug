package jwtdebug

import (
	"errors"
	"strings"
	"testing"
)

func TestParseArgs(t *testing.T) {
	tests := map[string]struct {
		args      []string
		check     func(t *testing.T, parsed parsedArgs)
		wantErr   string
		wantErrIs error
	}{
		"all enables every display": {
			args: []string{"--all"},
			check: func(t *testing.T, parsed parsedArgs) {
				t.Helper()
				if !parsed.flags.header || !parsed.flags.claims ||
					!parsed.flags.signature || !parsed.flags.expiration {
					t.Fatalf("--all did not enable every display flag: %+v", parsed.flags)
				}
			},
		},
		"claims can be disabled Go style": {
			args: []string{"-claims=false"},
			check: func(t *testing.T, parsed parsedArgs) {
				t.Helper()
				if parsed.flags.claims {
					t.Fatal("claims remained enabled")
				}
			},
		},
		"short flags can be clustered": {
			args: []string{"-Hcs"},
			check: func(t *testing.T, parsed parsedArgs) {
				t.Helper()
				if !parsed.flags.header || !parsed.flags.claims || !parsed.flags.signature {
					t.Fatalf("cluster was not parsed: %+v", parsed.flags)
				}
			},
		},
		"flags can follow tokens": {
			args: []string{"first", "--quiet", "second"},
			check: func(t *testing.T, parsed parsedArgs) {
				t.Helper()
				if !parsed.flags.quiet {
					t.Fatal("quiet flag was not parsed")
				}
				if got, want := strings.Join(parsed.tokens, ","), "first,second"; got != want {
					t.Fatalf("tokens = %q, want %q", got, want)
				}
			},
		},
		"double dash ends option parsing": {
			args: []string{"--", "--quiet"},
			check: func(t *testing.T, parsed parsedArgs) {
				t.Helper()
				if parsed.flags.quiet || len(parsed.tokens) != 1 || parsed.tokens[0] != "--quiet" {
					t.Fatalf("unexpected parse result: %+v", parsed)
				}
			},
		},
		"deprecated key aliases": {
			args: []string{"-key", "greendale.key"},
			check: func(t *testing.T, parsed parsedArgs) {
				t.Helper()
				if parsed.flags.keyFile != "greendale.key" {
					t.Fatalf("key file = %q", parsed.flags.keyFile)
				}
				if len(parsed.warnings) != 1 || !strings.Contains(parsed.warnings[0], "deprecated") {
					t.Fatalf("warnings = %v", parsed.warnings)
				}
			},
		},
		"current key wins over deprecated key": {
			args: []string{"--key", "old.key", "--key-file", "new.key"},
			check: func(t *testing.T, parsed parsedArgs) {
				t.Helper()
				if parsed.flags.keyFile != "new.key" {
					t.Fatalf("key file = %q", parsed.flags.keyFile)
				}
			},
		},
		"algorithm requires verification": {
			args:    []string{"--algorithm", "HS256"},
			wantErr: "requires --verify",
		},
		"unknown option": {
			args:    []string{"--bogus"},
			wantErr: "unexpected argument",
		},
		"help": {
			args:      []string{"-help"},
			wantErrIs: errHelp,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			parsed, err := parseArgs(tc.args)
			if tc.wantErrIs != nil {
				if !errors.Is(err, tc.wantErrIs) {
					t.Fatalf("error = %v, want %v", err, tc.wantErrIs)
				}
				return
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse args: %v", err)
			}
			tc.check(t, parsed)
		})
	}
}
