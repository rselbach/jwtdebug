package jwtdebug

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
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

func TestCLIReadsExplicitStdinAmongArguments(t *testing.T) {
	argument := unsignedJWT(t, map[string]any{"sub": "Argument Token"})
	standardInput := unsignedJWT(t, map[string]any{"sub": "Stdin Token"})
	result := runCLI(t, []string{"--quiet", argument, "-"}, standardInput+"\n")
	if result.exitCode != exitSuccess {
		t.Fatalf("result = %+v", result)
	}
	for _, want := range []string{"Argument Token", "Stdin Token"} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("stdout missing %q: %s", want, result.stdout)
		}
	}
}

func TestCLIRejectsOversizedInputsAndContinuesStdin(t *testing.T) {
	atLimit := runCLI(t, []string{strings.Repeat("x", maxTokenInputSize)}, "")
	if strings.Contains(atLimit.stderr, "exceeds maximum size") {
		t.Fatalf("at-limit argument was rejected as oversized: %+v", atLimit)
	}

	oversized := strings.Repeat("x", maxTokenInputSize+1)
	argument := runCLI(t, []string{oversized}, "")
	if argument.exitCode != exitInvalidToken || !strings.Contains(argument.stderr, "exceeds maximum size") {
		t.Fatalf("oversized argument result = %+v", argument)
	}

	valid := unsignedJWT(t, map[string]any{"sub": "After Oversized Input"})
	standardInput := runCLI(t, []string{"--quiet"}, oversized+"\n"+valid+"\n")
	if standardInput.exitCode != exitInvalidToken ||
		!strings.Contains(standardInput.stderr, "exceeds maximum size") ||
		!strings.Contains(standardInput.stdout, "After Oversized Input") {
		t.Fatalf("oversized stdin result = %+v", standardInput)
	}
}

type errorAfterDataReader struct {
	data []byte
	err  error
}

func (r *errorAfterDataReader) Read(buffer []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	read := copy(buffer, r.data)
	r.data = r.data[read:]
	return read, nil
}

func TestCLIStdinRetainsTokenFailureBeforeReadError(t *testing.T) {
	readErr := errors.New("read failed")
	reader := &errorAfterDataReader{data: []byte("not-a-token\n"), err: readErr}
	var stdout strings.Builder
	var stderr strings.Builder
	out := newOutput(&stdout, &stderr)

	exitCode := run([]string{"--quiet"}, reader, false, out)
	if exitCode != exitInvalidToken {
		t.Fatalf("exit code = %d, want %d", exitCode, exitInvalidToken)
	}
	for _, want := range []string{"invalid token format", "failed to read stdin: read failed"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q: %s", want, stderr.String())
		}
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

func TestResolvedVersionUsesInjectedValueOrDevelopmentFallback(t *testing.T) {
	originalVersion := version
	t.Cleanup(func() { version = originalVersion })

	version = "v2.3.4"
	if got := resolvedVersion(); got != "2.3.4" {
		t.Fatalf("injected version = %q", got)
	}

	version = ""
	if got := resolvedVersion(); got != "devel" {
		t.Fatalf("development version = %q", got)
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

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
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

func TestWrappedMixedOutputErrorsDoNotExitSuccessfully(t *testing.T) {
	writeErr := errors.New("write failed")
	mixed := fmt.Errorf("wrapped output error: %w", errors.Join(io.ErrClosedPipe, writeErr))
	if isOnlyBrokenPipe(mixed) {
		t.Fatalf("mixed output error classified as only broken pipes: %v", mixed)
	}
	if got := finalExitCode(exitSuccess, mixed); got != exitError {
		t.Fatalf("final exit code = %d, want %d", got, exitError)
	}
}

func TestOutputStreamsFailIndependently(t *testing.T) {
	writeErr := errors.New("write failed")

	t.Run("stdout failure preserves stderr", func(t *testing.T) {
		var stderr strings.Builder
		out := newOutput(errorWriter{err: writeErr}, &stderr)
		out.stdoutLine("failed")
		out.stderrLine("diagnostic")
		if !errors.Is(out.finish(), writeErr) {
			t.Fatalf("output error = %v, want %v", out.finish(), writeErr)
		}
		if stderr.String() != "diagnostic\n" {
			t.Fatalf("stderr = %q", stderr.String())
		}
	})

	t.Run("stderr failure preserves stdout", func(t *testing.T) {
		var stdout strings.Builder
		out := newOutput(&stdout, errorWriter{err: writeErr})
		out.stderrLine("failed")
		out.stdoutLine("result")
		if !errors.Is(out.finish(), writeErr) {
			t.Fatalf("output error = %v, want %v", out.finish(), writeErr)
		}
		if stdout.String() != "result\n" {
			t.Fatalf("stdout = %q", stdout.String())
		}
	})
}

func TestRunDoesNotMaskOutputFailureWithDiagnosticBrokenPipe(t *testing.T) {
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open null device: %v", err)
	}
	t.Cleanup(func() { _ = stdin.Close() })

	exitCode := Run(
		[]string{"--help"},
		stdin,
		errorWriter{err: errors.New("output failed")},
		brokenWriter{},
	)
	if exitCode != exitError {
		t.Fatalf("exit code = %d, want %d", exitCode, exitError)
	}
}
