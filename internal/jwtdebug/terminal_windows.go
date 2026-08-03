//go:build windows

package jwtdebug

import (
	"os"
	"syscall"
)

func isTerminal(file *os.File) bool {
	var mode uint32
	err := syscall.GetConsoleMode(syscall.Handle(file.Fd()), &mode)
	return err == nil
}
