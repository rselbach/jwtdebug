package jwtdebug

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCLIRejectsInvalidTokens(t *testing.T) {
	result := runCLI(t, []string{"not-a-valid-token"}, "")
	if result.exitCode != exitInvalidToken {
		t.Fatalf("exit code = %d, want %d", result.exitCode, exitInvalidToken)
	}
	if !strings.Contains(result.stderr, "invalid token format") {
		t.Fatalf("stderr missing invalid format error: %q", result.stderr)
	}
}

func TestCLIDisplayFlags(t *testing.T) {
	token := tokenForParts(
		t,
		map[string]any{"alg": "none", "typ": "JWT"},
		map[string]any{"sub": "Abed Nadir"},
		[]byte("signature"),
	)

	tests := map[string]struct {
		args []string
		want []string
		not  []string
	}{
		"defaults to claims": {
			args: []string{"--quiet", token},
			want: []string{"CLAIMS:", `"sub": "Abed Nadir"`},
			not:  []string{"HEADER:", "SIGNATURE:", "EXPIRATION:"},
		},
		"header": {
			args: []string{"--quiet", "--header", "--claims=false", token},
			want: []string{"HEADER:", `"alg": "none"`},
			not:  []string{"CLAIMS:"},
		},
		"signature": {
			args: []string{"--quiet", "--signature", "--claims=false", token},
			want: []string{"SIGNATURE:", `"raw": "c2lnbmF0dXJl"`},
			not:  []string{"CLAIMS:"},
		},
		"all": {
			args: []string{"--quiet", "-all", token},
			want: []string{"HEADER:", "CLAIMS:", "SIGNATURE:", "EXPIRATION:"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result := runCLI(t, tc.args, "")
			if result.exitCode != exitSuccess {
				t.Fatalf("exit code = %d, stderr: %s", result.exitCode, result.stderr)
			}
			for _, want := range tc.want {
				if !strings.Contains(result.stdout, want) {
					t.Errorf("stdout missing %q:\n%s", want, result.stdout)
				}
			}
			for _, unwanted := range tc.not {
				if strings.Contains(result.stdout, unwanted) {
					t.Errorf("stdout unexpectedly contains %q:\n%s", unwanted, result.stdout)
				}
			}
		})
	}
}

func TestCLIUnverifiedNotice(t *testing.T) {
	token := unsignedJWT(t, map[string]any{"sub": "Troy Barnes"})

	result := runCLI(t, []string{token}, "")
	if !strings.Contains(result.stderr, "Note: claims are unverified") {
		t.Fatalf("stderr missing notice: %q", result.stderr)
	}

	quiet := runCLI(t, []string{"--quiet", token}, "")
	if quiet.stderr != "" {
		t.Fatalf("quiet stderr = %q, want empty", quiet.stderr)
	}

	raw := runCLI(t, []string{"--raw-claims", token}, "")
	if raw.stderr != "" || strings.Contains(raw.stdout, "CLAIMS:") {
		t.Fatalf("raw output was not machine-readable: stdout=%q stderr=%q", raw.stdout, raw.stderr)
	}
}

func TestCLISmartExtraction(t *testing.T) {
	token := unsignedJWT(t, map[string]any{"sub": "Pierce Hawthorne"})
	inputs := map[string]string{
		"bearer": "Bearer " + token,
		"cookie": "Set-Cookie: session=" + token + "; HttpOnly",
		"JSON":   `{"access_token":"` + token + `"}`,
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			result := runCLI(t, []string{"--quiet", input}, "")
			if result.exitCode != exitSuccess || !strings.Contains(result.stdout, "Pierce Hawthorne") {
				t.Fatalf("extraction failed: %+v", result)
			}
		})
	}

	strict := runCLI(t, []string{"--strict", "Bearer " + token}, "")
	if strict.exitCode != exitInvalidToken {
		t.Fatalf("strict exit code = %d", strict.exitCode)
	}
}

func TestCLIVerboseDiagnostics(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-bytes-long!")
	token := hmacJWT(t, secret, map[string]any{"sub": "Verbose Dean"})
	keyFile := writeTestKey(t, secret)
	result := runCLI(t, []string{
		"--verbose",
		"--verify",
		"--algorithm", "HS256",
		"--key-file", keyFile,
		"Bearer " + token,
	}, "")

	if result.exitCode != exitSuccess {
		t.Fatalf("exit code = %d, stderr: %s", result.exitCode, result.stderr)
	}
	for _, want := range []string{
		"verbose: extracted JWT from input",
		`verbose: header alg="HS256"`,
		"verbose: verifying signature with key file",
		"verbose: signature verification succeeded",
	} {
		if !strings.Contains(result.stderr, want) {
			t.Errorf("stderr missing %q:\n%s", want, result.stderr)
		}
	}
}

func TestCLIProcessesEveryInputAndKeepsFirstFailure(t *testing.T) {
	first := unsignedJWT(t, map[string]any{"sub": "First Token"})
	last := unsignedJWT(t, map[string]any{"sub": "Last Token"})

	arguments := runCLI(t, []string{"--quiet", first, "not-a-token", last}, "")
	if arguments.exitCode != exitInvalidToken {
		t.Fatalf("argument exit code = %d", arguments.exitCode)
	}
	for _, want := range []string{"First Token", "Last Token"} {
		if !strings.Contains(arguments.stdout, want) {
			t.Errorf("argument stdout missing %q: %s", want, arguments.stdout)
		}
	}

	stdin := runCLI(t, []string{"--quiet"}, first+"\nnot-a-token\n"+last+"\n")
	if stdin.exitCode != exitInvalidToken {
		t.Fatalf("stdin exit code = %d", stdin.exitCode)
	}
	for _, want := range []string{"First Token", "Last Token"} {
		if !strings.Contains(stdin.stdout, want) {
			t.Errorf("stdin stdout missing %q: %s", want, stdin.stdout)
		}
	}
}

func TestCLIFirstFailureDeterminesExitCode(t *testing.T) {
	secret := []byte("test-secret-key-at-least-32-bytes-long!")
	token := hmacJWT(t, secret, map[string]any{"sub": "Annie Edison"})
	result := runCLI(t, []string{
		"--verify", "--algorithm", "HS256",
		"--key-file", writeTestKey(t, []byte("wrong-secret-key-at-least-32-bytes!!!!!")),
		"not-a-valid-token",
		token,
	}, "")
	if result.exitCode != exitInvalidToken {
		t.Fatalf("exit code = %d, want first failure %d", result.exitCode, exitInvalidToken)
	}
	for _, want := range []string{"invalid token format", "signature is invalid"} {
		if !strings.Contains(result.stderr, want) {
			t.Errorf("stderr missing %q: %s", want, result.stderr)
		}
	}
}

func TestCLIReadsExplicitStdin(t *testing.T) {
	token := unsignedJWT(t, map[string]any{"sub": "Dash Stdin Test"})
	result := runCLI(t, []string{"--quiet", "-"}, token+"\n")
	if result.exitCode != exitSuccess || !strings.Contains(result.stdout, "Dash Stdin Test") {
		t.Fatalf("explicit stdin failed: %+v", result)
	}
}

func TestCLIEmptyStdinIsGeneralError(t *testing.T) {
	result := runCLI(t, nil, "")
	if result.exitCode != exitError || !strings.Contains(result.stderr, "no token provided on stdin") {
		t.Fatalf("empty stdin result: %+v", result)
	}
}

func TestCLIInteractiveStdinShowsUsageOrPrompt(t *testing.T) {
	tests := map[string]struct {
		args []string
		want string
	}{
		"implicit": {want: "Error: no token provided"},
		"explicit": {args: []string{"-"}, want: "Reading token from stdin"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			out := newOutput(&stdout, &stderr)
			exitCode := run(tc.args, strings.NewReader(""), true, out)
			if exitCode != exitError || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("exit=%d stderr=%q", exitCode, stderr.String())
			}
		})
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	for _, helpFlag := range []string{"--help", "-help", "-h"} {
		result := runCLI(t, []string{helpFlag}, "")
		if result.exitCode != exitSuccess || result.stderr != "" {
			t.Fatalf("help %s result: %+v", helpFlag, result)
		}
		for _, want := range []string{
			"Usage: jwtdebug [OPTIONS] [token]...",
			"Options:",
			"--algorithm <algorithm>",
			"Exit codes:",
		} {
			if !strings.Contains(result.stdout, want) {
				t.Errorf("help missing %q", want)
			}
		}
	}

	result := runCLI(t, []string{"--version"}, "")
	if result.exitCode != exitSuccess ||
		!strings.Contains(result.stdout, "jwtdebug version "+resolvedVersion()) {
		t.Fatalf("version result: %+v", result)
	}
}

func TestCLIDeprecatedFlagsWarn(t *testing.T) {
	token := unsignedJWT(t, map[string]any{"sub": "Greendale Human Being"})
	result := runCLI(t, []string{"-expiry", "-ignore-exp", "--quiet", token}, "")
	if result.exitCode != exitSuccess {
		t.Fatalf("exit code = %d", result.exitCode)
	}
	for _, want := range []string{
		"Warning: --expiry is deprecated",
		"Warning: --ignore-exp is deprecated",
		"EXPIRATION:",
	} {
		combined := result.stdout + result.stderr
		if !strings.Contains(combined, want) {
			t.Errorf("output missing %q: %s", want, combined)
		}
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestBrokenPipeExitsSuccessfully(t *testing.T) {
	out := newOutput(brokenWriter{}, io.Discard)
	exitCode := run([]string{"--help"}, strings.NewReader(""), false, out)
	err := out.finish()
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output error = %v, want closed pipe", err)
	}
	if got := finalExitCode(exitCode, err); got != exitSuccess {
		t.Fatalf("final exit code = %d", got)
	}
}
