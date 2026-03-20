package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// testToken generates a valid HS256 JWT with the given claims and key.
func testToken(t *testing.T, claims jwt.MapClaims, key string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(key))
	require.NoError(t, err)
	return signed
}

// captureStdout captures stdout during f() and returns the output.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

// captureStderr captures stderr during f() and returns the output.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()

	old := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w

	f()

	w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

// withArgs runs f with os.Args set to args, resetting flag.CommandLine afterwards.
func withArgs(t *testing.T, args []string, f func()) {
	t.Helper()
	oldArgs := os.Args
	os.Args = args
	// Reset the global flag set so InitFlags can re-register
	flag.CommandLine = flag.NewFlagSet("jwtdebug", flag.ContinueOnError)
	defer func() { os.Args = oldArgs }()
	f()
}

func TestRunDecodeBasic(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub":  "Troy Barnes",
		"name": "Greendale Human Being",
		"iat":  now.Add(-time.Hour).Unix(),
		"exp":  now.Add(time.Hour).Unix(),
		"role": "student",
	}, key)

	withArgs(t, []string{"jwtdebug", "--no-color", "--claims", token}, func() {
		code := run()
		r.Equal(0, code)
	})
}

func TestRunDecodeRawClaims(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Abed Nadir",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	withArgs(t, []string{"jwtdebug", "--no-color", "--raw-claims", token}, func() {
		output := captureStdout(t, func() {
			code := run()
			r.Equal(0, code)
		})
		r.Contains(output, `"sub": "Abed Nadir"`)
	})
}

func TestRunVerifySignature(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Annie Edison",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	keyFile, err := os.CreateTemp("", "jwtdebug-test-key-*.txt")
	r.NoError(err)
	defer os.Remove(keyFile.Name())
	_, err = keyFile.WriteString(key)
	r.NoError(err)
	keyFile.Close()

	withArgs(t, []string{"jwtdebug", "--no-color", "--verify", "--key-file", keyFile.Name(), token}, func() {
		code := run()
		r.Equal(0, code)
	})
}

func TestRunVerifyInvalidSignature(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Señor Chang",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	wrongKey := "wrong-key-that-is-at-least-32-bytes!!"
	wrongKeyFile, err := os.CreateTemp("", "jwtdebug-wrong-key-*.txt")
	r.NoError(err)
	defer os.Remove(wrongKeyFile.Name())
	_, err = wrongKeyFile.WriteString(wrongKey)
	r.NoError(err)
	wrongKeyFile.Close()

	withArgs(t, []string{"jwtdebug", "--no-color", "--verify", "--key-file", wrongKeyFile.Name(), token}, func() {
		code := run()
		r.Equal(3, code, "Expected verification failure exit code")
	})
}

func TestRunNoTokenShowsHelp(t *testing.T) {
	r := require.New(t)

	withArgs(t, []string{"jwtdebug", "--no-color"}, func() {
		stderr := captureStderr(t, func() {
			code := run()
			r.Equal(1, code, "Expected general error exit code for no token")
		})
		r.Contains(stderr, "no token provided")
	})
}

func TestRunInvalidToken(t *testing.T) {
	r := require.New(t)

	withArgs(t, []string{"jwtdebug", "--no-color", "not-a-valid-token"}, func() {
		code := run()
		r.Equal(2, code, "Expected invalid token exit code")
	})
}

func TestRunVersion(t *testing.T) {
	r := require.New(t)

	withArgs(t, []string{"jwtdebug", "--version"}, func() {
		output := captureStdout(t, func() {
			code := run()
			r.Equal(0, code)
		})
		r.Contains(output, "jwtdebug version")
	})
}

func TestRunExpirationCheck(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	expiredToken := testToken(t, jwt.MapClaims{
		"sub": "Britta Perry",
		"exp": now.Add(-time.Hour).Unix(),
	}, key)
	validToken := testToken(t, jwt.MapClaims{
		"sub": "Britta Perry",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	// Both should exit 0 regardless of expiration status — expiration is informational
	withArgs(t, []string{"jwtdebug", "--no-color", "--expiration", "--claims=false", expiredToken}, func() {
		code := run()
		r.Equal(0, code)
	})

	withArgs(t, []string{"jwtdebug", "--no-color", "--expiration", "--claims=false", validToken}, func() {
		code := run()
		r.Equal(0, code)
	})
}

func TestRunOutputFormats(t *testing.T) {
	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Jeff Winger",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	formats := []string{"pretty", "json", "raw"}
	for _, format := range formats {
		t.Run(format, func(t *testing.T) {
			r := require.New(t)

			withArgs(t, []string{"jwtdebug", "--no-color", "--output", format, "--claims", token}, func() {
				output := captureStdout(t, func() {
					code := run()
					r.Equal(0, code)
				})
				r.Contains(output, "Jeff Winger")
			})
		})
	}
}

func TestRunSmartExtraction(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Pierce Hawthorne",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	withArgs(t, []string{"jwtdebug", "--no-color", "--claims", "Bearer " + token}, func() {
		output := captureStdout(t, func() {
			code := run()
			r.Equal(0, code)
		})
		r.Contains(output, "Pierce Hawthorne")
	})
}

func TestRunStrictModeRejectsBearer(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Shirley Bennett",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	withArgs(t, []string{"jwtdebug", "--no-color", "--strict", "Bearer " + token}, func() {
		code := run()
		r.Equal(2, code, "Strict mode should reject Bearer prefix")
	})
}

func TestRunHelpFlag(t *testing.T) {
	r := require.New(t)

	withArgs(t, []string{"jwtdebug", "--help"}, func() {
		stderr := captureStderr(t, func() {
			code := run()
			r.Equal(0, code)
		})
		r.Contains(stderr, "Usage:")
		r.Contains(stderr, "Options:")
	})
}
