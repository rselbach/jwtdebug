package jwtdebug

import (
	"fmt"
	"io"
)

// output writes application output and retains the first write error.
type output struct {
	stdout io.Writer
	stderr io.Writer
	err    error
}

func newOutput(stdout, stderr io.Writer) *output {
	return &output{stdout: stdout, stderr: stderr}
}

func (o *output) stdoutLine(format string, args ...any) {
	if o.err != nil {
		return
	}

	_, o.err = fmt.Fprintf(o.stdout, format+"\n", args...)
}

func (o *output) stderrLine(format string, args ...any) {
	if o.err != nil {
		return
	}

	_, o.err = fmt.Fprintf(o.stderr, format+"\n", args...)
}

func (o *output) stdoutText(text string) {
	if o.err != nil {
		return
	}

	_, o.err = io.WriteString(o.stdout, text)
}

func (o *output) stderrText(text string) {
	if o.err != nil {
		return
	}

	_, o.err = io.WriteString(o.stderr, text)
}

func (o *output) finish() error {
	return o.err
}
