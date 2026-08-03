//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package jwtdebug

import (
	"errors"
	"os/signal"
	"syscall"
)

// ignoreSIGPIPE lets writes return EPIPE so the CLI can exit cleanly when a
// downstream command closes its input early.
func ignoreSIGPIPE() {
	signal.Ignore(syscall.SIGPIPE)
}

func isPlatformBrokenPipe(err error) bool {
	return errors.Is(err, syscall.EPIPE)
}
