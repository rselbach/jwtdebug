//go:build !aix && !darwin && !dragonfly && !freebsd && !illumos && !linux && !netbsd && !openbsd && !solaris && !windows

package jwtdebug

func ignoreSIGPIPE() {}

func isPlatformBrokenPipe(_ error) bool {
	return false
}
