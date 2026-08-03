//go:build windows

package jwtdebug

import (
	"errors"
	"syscall"
)

func ignoreSIGPIPE() {}

func isPlatformBrokenPipe(err error) bool {
	return errors.Is(err, syscall.ERROR_BROKEN_PIPE)
}
