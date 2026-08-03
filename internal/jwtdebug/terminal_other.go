//go:build !darwin && !linux && !windows

package jwtdebug

import "os"

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
