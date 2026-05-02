package main

import (
	"bytes"
	"io"
	"os"
	"testing"
	"time"

	"github.com/fatih/color"
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
	oldColorOut := color.Output
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	color.Output = w

	defer func() {
		os.Stdout = old
		color.Output = oldColorOut
		r.Close()
	}()

	f()
	w.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
}

// captureStderr captures stderr during f() and returns the output.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()

	old := os.Stderr
	oldColorErr := color.Error
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	color.Error = w

	defer func() {
		os.Stderr = old
		color.Error = oldColorErr
		r.Close()
	}()

	f()
	w.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)
	return buf.String()
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

	code := runWithArgs([]string{"--claims", token})
	r.Equal(0, code)
}

func TestRunDecodeRawClaims(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Abed Nadir",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	output := captureStdout(t, func() {
		code := runWithArgs([]string{"--raw-claims", token})
		r.Equal(0, code)
	})
	r.Contains(output, `"sub": "Abed Nadir"`)
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

	code := runWithArgs([]string{"--verify", "--key-file", keyFile.Name(), token})
	r.Equal(0, code)
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

	code := runWithArgs([]string{"--verify", "--key-file", wrongKeyFile.Name(), token})
	r.Equal(3, code, "Expected verification failure exit code")
}

func TestRunNoTokenShowsHelp(t *testing.T) {
	r := require.New(t)

	stderr := captureStderr(t, func() {
		code := runWithArgs([]string{})
		r.Equal(1, code, "Expected general error exit code for no token")
	})
	r.Contains(stderr, "no token provided")
}

func TestRunInvalidToken(t *testing.T) {
	r := require.New(t)

	code := runWithArgs([]string{"not-a-valid-token"})
	r.Equal(2, code, "Expected invalid token exit code")
}

func TestRunVersion(t *testing.T) {
	r := require.New(t)

	output := captureStdout(t, func() {
		code := runWithArgs([]string{"--version"})
		r.Equal(0, code)
	})
	r.Contains(output, "jwtdebug version")
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
	code := runWithArgs([]string{"--expiration", "--claims=false", expiredToken})
	r.Equal(0, code)

	code = runWithArgs([]string{"--expiration", "--claims=false", validToken})
	r.Equal(0, code)
}

func TestRunSmartExtraction(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Pierce Hawthorne",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	output := captureStdout(t, func() {
		code := runWithArgs([]string{"--claims", "Bearer " + token})
		r.Equal(0, code)
	})
	r.Contains(output, "Pierce Hawthorne")
}

func TestRunStrictModeRejectsBearer(t *testing.T) {
	r := require.New(t)

	key := "test-secret-key-at-least-32-bytes-long!"
	now := time.Now()
	token := testToken(t, jwt.MapClaims{
		"sub": "Shirley Bennett",
		"exp": now.Add(time.Hour).Unix(),
	}, key)

	code := runWithArgs([]string{"--strict", "Bearer " + token})
	r.Equal(2, code, "Strict mode should reject Bearer prefix")
}

func TestRunHelpFlag(t *testing.T) {
	r := require.New(t)

	stderr := captureStderr(t, func() {
		code := runWithArgs([]string{"--help"})
		r.Equal(0, code)
	})
	r.Contains(stderr, "Usage:")
	r.Contains(stderr, "Display:")
}
