package jwtdebug

import (
	"os"
	"testing"
)

func TestNullDeviceIsNotTerminal(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open null device: %v", err)
	}
	if isTerminal(file) {
		t.Error("null device reported as a terminal")
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close null device: %v", err)
	}
}
