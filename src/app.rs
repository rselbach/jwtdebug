use std::ffi::OsString;
use std::io::BufRead;

use serde_json::Value;

use crate::cli::{self, Flags};
use crate::constants::{
    EXIT_ERROR, EXIT_INVALID_TOKEN, EXIT_SUCCESS, EXIT_VERIFICATION_FAIL, MAX_INPUT_SIZE,
};
use crate::expiration;
use crate::output::Output;
use crate::parser::{ParsedToken, resolve_token};
use crate::time_claims::UnixTime;
use crate::verification::Verifier;

type VerifierState = Option<Result<Verifier, String>>;

pub fn run<I, T>(
    args: I,
    stdin: &mut dyn BufRead,
    stdin_is_terminal: bool,
    output: &mut Output<'_>,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let parsed = match cli::parse(args) {
        Ok(parsed) => parsed,
        Err(error) if error.kind() == clap::error::ErrorKind::DisplayHelp => {
            output.stdout_text(&error.to_string());
            return EXIT_SUCCESS;
        }
        Err(error) => {
            output.stderr_text(&error.to_string());
            return EXIT_ERROR;
        }
    };

    for warning in parsed.warnings {
        output.stderr_line(format_args!("{warning}"));
    }
    if parsed.flags.show_version {
        print_version(&parsed.flags, output);
        return EXIT_SUCCESS;
    }

    Processor {
        flags: &parsed.flags,
        verifier: None,
        output,
    }
    .process_inputs(&parsed.tokens, stdin, stdin_is_terminal)
}

fn print_version(flags: &Flags, output: &mut Output<'_>) {
    output.stdout_line(format_args!(
        "jwtdebug version {}",
        cli::VERSION.strip_prefix('v').unwrap_or(cli::VERSION)
    ));
    if flags.verbose || cli::COMMIT != "unknown" {
        output.stdout_line(format_args!("  commit:     {}", cli::COMMIT));
        output.stdout_line(format_args!("  built:      {}", cli::BUILD_DATE));
    }
}

struct Processor<'a, 'output> {
    flags: &'a Flags,
    verifier: VerifierState,
    output: &'a mut Output<'output>,
}

impl Processor<'_, '_> {
    fn process_inputs(
        &mut self,
        tokens: &[String],
        stdin: &mut dyn BufRead,
        stdin_is_terminal: bool,
    ) -> i32 {
        if tokens.is_empty() {
            return self.process_stdin(stdin, stdin_is_terminal, false);
        }

        let mut exit_code = EXIT_SUCCESS;
        let mut stdin_consumed = false;
        for token in tokens {
            let current = if token == "-" {
                if stdin_consumed {
                    self.output.stderr_line(format_args!(
                        "Error: stdin marker '-' may only be specified once"
                    ));
                    EXIT_ERROR
                } else {
                    stdin_consumed = true;
                    self.process_stdin(stdin, stdin_is_terminal, true)
                }
            } else {
                self.process_token(token)
            };
            exit_code = retain_first_failure(exit_code, current);
        }
        exit_code
    }

    fn process_token(&mut self, input: &str) -> i32 {
        if input.trim().len() > MAX_INPUT_SIZE {
            self.print_oversized_input();
            return EXIT_INVALID_TOKEN;
        }
        let parsed = match resolve_token(input, self.flags.strict) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.output.stderr_line(format_args!("Error: {error}"));
                return EXIT_INVALID_TOKEN;
            }
        };
        self.log_parsed_token(input, &parsed);

        if self.flags.verify_signature {
            self.log_verbose(format_args!(
                "verifying signature with key file {:?} (ignore-expiration={})",
                self.flags.key_file.as_deref().unwrap_or(""),
                self.flags.ignore_expiration
            ));
            if self.verifier.is_none() {
                let initialized = Verifier::new(
                    self.flags.key_file.as_deref(),
                    self.flags.algorithm.as_deref(),
                    self.flags.ignore_expiration,
                )
                .map_err(|error| error.to_string());
                if let Ok(verifier) = &initialized
                    && let Some(warning) = verifier.weak_hmac_key_warning()
                {
                    self.output.stderr_line(format_args!(
                        "Warning: HMAC key is {} bytes; RFC 7518 requires at least {} for this algorithm",
                        warning.actual, warning.minimum
                    ));
                }
                self.verifier = Some(initialized);
            }

            let verification = self
                .verifier
                .as_ref()
                .expect("verifier state was initialized");
            let result = match verification {
                Err(message) => Err(message.clone()),
                Ok(verifier) => verifier
                    .verify(&parsed, UnixTime::now())
                    .map_err(|error| error.to_string()),
            };
            if let Err(message) = result {
                self.print_verification_failure(&message);
                return EXIT_VERIFICATION_FAIL;
            }
            self.log_verbose(format_args!("signature verification succeeded"));
        }

        if self.flags.raw_claims {
            match serde_json::to_string_pretty(&parsed.claims) {
                Ok(data) => self.output.stdout_line(format_args!("{data}")),
                Err(error) => {
                    self.output.stderr_line(format_args!(
                        "Error: failed to encode claims as JSON: {error}"
                    ));
                    return EXIT_ERROR;
                }
            }
            return EXIT_SUCCESS;
        }

        if !self.flags.verify_signature && !self.flags.quiet {
            self.output.stderr_line(format_args!(
                "Note: claims are unverified. Use --verify --key-file --algorithm to validate."
            ));
        }
        if self.flags.header && !self.print_json_block("HEADER", &parsed.header) {
            return EXIT_ERROR;
        }
        if self.flags.claims && !self.print_json_block("CLAIMS", &parsed.claims) {
            return EXIT_ERROR;
        }
        if self.flags.signature {
            let signature = serde_json::json!({ "raw": parsed.signature });
            if !self.print_json_block("SIGNATURE", &signature) {
                return EXIT_ERROR;
            }
        }
        if self.flags.expiration {
            expiration::check(&parsed.claims, UnixTime::now(), self.output);
        }
        if self.flags.verify_signature {
            self.output
                .stdout_line(format_args!("Signature verified successfully"));
        }
        EXIT_SUCCESS
    }

    fn process_stdin(
        &mut self,
        stdin: &mut dyn BufRead,
        stdin_is_terminal: bool,
        explicit: bool,
    ) -> i32 {
        if stdin_is_terminal {
            if !explicit {
                print_usage_hint(self.output);
                return EXIT_ERROR;
            }
            if !self.flags.quiet {
                self.output.stderr_line(format_args!(
                    "Reading token from stdin... (press Ctrl+D when done)"
                ));
            }
        }

        let mut has_token = false;
        let mut exit_code = EXIT_SUCCESS;
        loop {
            let line = match read_input_line(stdin) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(error) => {
                    self.output
                        .stderr_line(format_args!("Error: failed to read stdin: {error}"));
                    return retain_first_failure(exit_code, EXIT_ERROR);
                }
            };
            match line {
                InputLine::Oversized => {
                    has_token = true;
                    self.print_oversized_input();
                    exit_code = retain_first_failure(exit_code, EXIT_INVALID_TOKEN);
                }
                InputLine::Data(line) => {
                    let Ok(line) = std::str::from_utf8(&line) else {
                        has_token = true;
                        self.output
                            .stderr_line(format_args!("Error: token input is not valid UTF-8"));
                        exit_code = retain_first_failure(exit_code, EXIT_INVALID_TOKEN);
                        continue;
                    };
                    let line = line.trim();
                    if !line.is_empty() {
                        has_token = true;
                        let current = self.process_token(line);
                        exit_code = retain_first_failure(exit_code, current);
                    }
                }
            }
        }

        if !has_token {
            self.output
                .stderr_line(format_args!("Error: no token provided on stdin"));
            EXIT_ERROR
        } else {
            exit_code
        }
    }

    fn print_json_block(&mut self, name: &str, value: &impl serde::Serialize) -> bool {
        match serde_json::to_string_pretty(value) {
            Ok(data) => {
                self.output.stdout_line(format_args!("{name}:"));
                self.output.stdout_line(format_args!("{data}"));
                self.output.stdout_line(format_args!(""));
                true
            }
            Err(error) => {
                self.output.stderr_line(format_args!(
                    "Error: failed to encode {} as JSON: {error}",
                    name.to_ascii_lowercase()
                ));
                false
            }
        }
    }

    fn print_verification_failure(&mut self, error: &impl std::fmt::Display) {
        self.output
            .stderr_line(format_args!("Signature verification failed: {error}"));
    }

    fn print_oversized_input(&mut self) {
        self.output.stderr_line(format_args!(
            "Error: token input exceeds maximum size of {MAX_INPUT_SIZE} bytes"
        ));
    }

    fn log_parsed_token(&mut self, input: &str, parsed: &ParsedToken) {
        if !self.flags.verbose {
            return;
        }
        let input = input.trim();
        if input == parsed.raw {
            self.log_verbose(format_args!("using token ({} bytes)", parsed.raw.len()));
        } else {
            self.log_verbose(format_args!(
                "extracted JWT from input ({} bytes -> {} bytes)",
                input.len(),
                parsed.raw.len()
            ));
        }
        let algorithm = parsed
            .header
            .get("alg")
            .map(Value::to_string)
            .unwrap_or_else(|| "<missing>".to_owned());
        self.log_verbose(format_args!("header alg={algorithm}"));
    }

    fn log_verbose(&mut self, arguments: std::fmt::Arguments<'_>) {
        if self.flags.verbose {
            self.output
                .stderr_line(format_args!("verbose: {arguments}"));
        }
    }
}

fn retain_first_failure(seen: i32, current: i32) -> i32 {
    if seen == EXIT_SUCCESS { current } else { seen }
}

enum InputLine {
    Data(Vec<u8>),
    Oversized,
}

/// Reads and drains one line while retaining at most 1 MiB plus a CRLF. This
/// bounds memory even when stdin supplies a line without a terminator.
fn read_input_line(reader: &mut dyn BufRead) -> std::io::Result<Option<InputLine>> {
    let mut data = Vec::new();
    let mut oversized = false;
    let mut saw_data = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if saw_data {
                Ok(Some(if oversized {
                    InputLine::Oversized
                } else {
                    InputLine::Data(data)
                }))
            } else {
                Ok(None)
            };
        }

        saw_data = true;
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        if !oversized {
            if data.len() + consumed > MAX_INPUT_SIZE + 2 {
                oversized = true;
                data.clear();
            } else {
                data.extend_from_slice(&buffer[..consumed]);
            }
        }
        reader.consume(consumed);

        if newline.is_some() {
            return Ok(Some(if oversized {
                InputLine::Oversized
            } else {
                InputLine::Data(data)
            }));
        }
    }
}

fn print_usage_hint(output: &mut Output<'_>) {
    output.stderr_text(
        "Error: no token provided\n\n\
         Usage: jwtdebug [options] <token>\n\
                jwtdebug [options] -           # read from stdin\n\
                command | jwtdebug [options]   # read from pipe\n\n\
         Run 'jwtdebug --help' for more information.\n",
    );
}
