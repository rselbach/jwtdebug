package jwtdebug

import (
	"errors"
	"fmt"
	"io"
)

// output writes application output and retains the first error for each stream.
type output struct {
	stdout    io.Writer
	stderr    io.Writer
	stdoutErr error
	stderrErr error
}

func newOutput(stdout, stderr io.Writer) *output {
	return &output{stdout: stdout, stderr: stderr}
}

func (o *output) stdoutLine(format string, args ...any) {
	if o.stdoutErr != nil {
		return
	}

	_, o.stdoutErr = fmt.Fprintf(o.stdout, format+"\n", args...)
}

func (o *output) stderrLine(format string, args ...any) {
	if o.stderrErr != nil {
		return
	}

	_, o.stderrErr = fmt.Fprintf(o.stderr, format+"\n", args...)
}

func (o *output) stdoutText(text string) {
	if o.stdoutErr != nil {
		return
	}

	_, o.stdoutErr = io.WriteString(o.stdout, text)
}

func (o *output) stderrText(text string) {
	if o.stderrErr != nil {
		return
	}

	_, o.stderrErr = io.WriteString(o.stderr, text)
}

func (o *output) finish() error {
	return errors.Join(o.stdoutErr, o.stderrErr)
}
