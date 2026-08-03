use std::fmt;
use std::io::{self, Write};

/// Application output that records the first write failure instead of
/// panicking through the standard printing macros.
pub struct Output<'a> {
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
    error: Option<io::Error>,
}

impl<'a> Output<'a> {
    pub fn new(stdout: &'a mut dyn Write, stderr: &'a mut dyn Write) -> Self {
        Self {
            stdout,
            stderr,
            error: None,
        }
    }

    pub fn stdout_line(&mut self, arguments: fmt::Arguments<'_>) {
        if self.error.is_some() {
            return;
        }

        let result = self
            .stdout
            .write_fmt(arguments)
            .and_then(|()| self.stdout.write_all(b"\n"));
        self.record(result);
    }

    pub fn stderr_line(&mut self, arguments: fmt::Arguments<'_>) {
        if self.error.is_some() {
            return;
        }

        let result = self
            .stderr
            .write_fmt(arguments)
            .and_then(|()| self.stderr.write_all(b"\n"));
        self.record(result);
    }

    pub fn stdout_text(&mut self, text: &str) {
        if self.error.is_some() {
            return;
        }

        let result = self.stdout.write_all(text.as_bytes());
        self.record(result);
    }

    pub fn stderr_text(&mut self, text: &str) {
        if self.error.is_some() {
            return;
        }

        let result = self.stderr.write_all(text.as_bytes());
        self.record(result);
    }

    pub fn finish(mut self) -> Option<io::Error> {
        if self.error.is_none() {
            let result = self.stdout.flush();
            self.record(result);
        }
        if self.error.is_none() {
            let result = self.stderr.flush();
            self.record(result);
        }

        self.error
    }

    fn record(&mut self, result: io::Result<()>) {
        if let Err(err) = result {
            self.error.get_or_insert(err);
        }
    }
}
