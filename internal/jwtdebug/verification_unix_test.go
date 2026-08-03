//go:build !windows

package jwtdebug

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFIFOKeyFileIsRejectedWithoutOpening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("create FIFO: %v", err)
	}
	token := unsignedJWT(t, map[string]any{"sub": "Greendale Intercom"})
	result := runCLI(t, []string{
		"--verify", "--algorithm", "HS256", "--key-file", path, token,
	}, "")
	if result.exitCode != exitVerificationFail ||
		!strings.Contains(result.stderr, "key file must be a regular file") {
		t.Fatalf("result = %+v", result)
	}
}
