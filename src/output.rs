use std::fmt;
use std::io::{self, Write};

pub(crate) fn escape_for_terminal(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

/// Fallible application output. Each stream retains its first error without
/// preventing the other stream from delivering diagnostics or results.
pub struct Output<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    stdout_error: Option<io::Error>,
    stderr_error: Option<io::Error>,
}

impl<'a> Output<'a> {
    pub fn new(stdout: &'a mut dyn Write, stderr: &'a mut dyn Write) -> Self {
        Self {
            stdout,
            stderr,
            stdout_error: None,
            stderr_error: None,
        }
    }

    pub fn stdout_line(&mut self, arguments: fmt::Arguments<'_>) {
        if self.stdout_error.is_some() {
            return;
        }
        self.stdout_error = self
            .stdout
            .write_fmt(arguments)
            .and_then(|()| self.stdout.write_all(b"\n"))
            .err();
    }

    pub fn stderr_line(&mut self, arguments: fmt::Arguments<'_>) {
        if self.stderr_error.is_some() {
            return;
        }
        self.stderr_error = self
            .stderr
            .write_fmt(arguments)
            .and_then(|()| self.stderr.write_all(b"\n"))
            .err();
    }

    pub fn stdout_text(&mut self, text: &str) {
        if self.stdout_error.is_none() {
            self.stdout_error = self.stdout.write_all(text.as_bytes()).err();
        }
    }

    pub fn stderr_text(&mut self, text: &str) {
        if self.stderr_error.is_none() {
            self.stderr_error = self.stderr.write_all(text.as_bytes()).err();
        }
    }

    pub fn finish(mut self) -> Option<OutputErrors> {
        if self.stdout_error.is_none() {
            self.stdout_error = self.stdout.flush().err();
        }
        if self.stderr_error.is_none() {
            self.stderr_error = self.stderr.flush().err();
        }

        (self.stdout_error.is_some() || self.stderr_error.is_some()).then_some(OutputErrors {
            stdout: self.stdout_error,
            stderr: self.stderr_error,
        })
    }
}

pub struct OutputErrors {
    stdout: Option<io::Error>,
    stderr: Option<io::Error>,
}

impl OutputErrors {
    pub fn only_broken_pipes(&self) -> bool {
        [&self.stdout, &self.stderr]
            .into_iter()
            .flatten()
            .all(|error| error.kind() == io::ErrorKind::BrokenPipe)
    }
}

impl fmt::Display for OutputErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.stdout, &self.stderr) {
            (Some(stdout), Some(stderr)) => write!(formatter, "{stdout}; {stderr}"),
            (Some(error), None) | (None, Some(error)) => error.fmt(formatter),
            (None, None) => Ok(()),
        }
    }
}
