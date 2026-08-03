//go:build linux

package jwtdebug

import (
	"os"
	"syscall"
	"unsafe"
)

func isTerminal(file *os.File) bool {
	var attributes syscall.Termios
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		file.Fd(),
		syscall.TCGETS,
		uintptr(unsafe.Pointer(&attributes)),
	)
	return err == 0
}
