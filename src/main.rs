mod cli;
mod constants;
mod expiration;
mod output;
mod parser;
mod printer;
mod time_claims;
mod verification;

use std::io::{self, BufRead, IsTerminal, Write};

use constants::{EXIT_ERROR, EXIT_INVALID_TOKEN, EXIT_SUCCESS, EXIT_VERIFICATION_FAIL};

type VerifierState = Option<Result<verification::Verifier, String>>;

fn main() {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let (exit_code, output_error) = {
        let mut stdout = stdout.lock();
        let mut stderr = stderr.lock();
        let mut output = output::Output::new(&mut stdout, &mut stderr);
        let exit_code = run(&mut output);
        (exit_code, output.finish())
    };

    if let Some(err) = output_error.as_ref() {
        if err.kind() != io::ErrorKind::BrokenPipe {
            let _ = writeln!(io::stderr().lock(), "Error: failed to write output: {err}");
        }
    }
    std::process::exit(final_exit_code(exit_code, output_error.as_ref()));
}

fn final_exit_code(exit_code: i32, output_error: Option<&io::Error>) -> i32 {
    match output_error.map(io::Error::kind) {
        None => exit_code,
        Some(io::ErrorKind::BrokenPipe) => EXIT_SUCCESS,
        Some(_) => EXIT_ERROR,
    }
}

fn run(output: &mut output::Output<'_>) -> i32 {
    run_with_args(std::env::args().skip(1), output)
}

fn run_with_args<I, T>(args: I, output: &mut output::Output<'_>) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let (flags, positional_args, warnings) = match cli::parse(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            if err.kind() == clap::error::ErrorKind::DisplayHelp {
                output.stdout_text(&err.to_string());
                return EXIT_SUCCESS;
            }

            output.stderr_text(&err.to_string());
            return EXIT_ERROR;
        }
    };

    for warning in warnings {
        output.stderr_line(format_args!("{warning}"));
    }

    if flags.show_version {
        print_version(&flags, output);
        return EXIT_SUCCESS;
    }

    process_input_tokens(&flags, &positional_args, output)
}

fn print_version(flags: &cli::Flags, output: &mut output::Output<'_>) {
    output.stdout_line(format_args!("jwtdebug version {}", cli::VERSION));
    if flags.verbose || cli::COMMIT != "unknown" {
        output.stdout_line(format_args!("  commit:     {}", cli::COMMIT));
        output.stdout_line(format_args!("  built:      {}", cli::BUILD_DATE));
    }
}

fn process_input_tokens(
    flags: &cli::Flags,
    args: &[String],
    output: &mut output::Output<'_>,
) -> i32 {
    let mut verifier = None;
    match args {
        [] => process_from_stdin(flags, false, &mut verifier, output),
        [arg] if arg == "-" => process_from_stdin(flags, true, &mut verifier, output),
        _ => {
            let mut exit_code = EXIT_SUCCESS;
            for token in args {
                exit_code = retain_first_failure(
                    exit_code,
                    process_token(token, flags, &mut verifier, output),
                );
            }
            exit_code
        }
    }
}

/// Report the first failure seen. Exit codes 2 and 3 describe different
/// problems rather than different severities, so there is no worst one to
/// pick; the first is the one the user can act on.
fn retain_first_failure(seen: i32, current: i32) -> i32 {
    if seen == EXIT_SUCCESS {
        current
    } else {
        seen
    }
}

fn process_token(
    input: &str,
    flags: &cli::Flags,
    verifier: &mut VerifierState,
    output: &mut output::Output<'_>,
) -> i32 {
    let parsed = match parser::resolve_token(input, flags.strict) {
        Ok(parsed) => parsed,
        Err(err) => {
            output.stderr_line(format_args!("Error: {err}"));
            return EXIT_INVALID_TOKEN;
        }
    };

    log_verbose_parse(flags, input, &parsed, output);

    if flags.verify_signature {
        log_verbose(
            flags,
            format!(
                "verifying signature with key file {:?} (ignore-expiration={})",
                flags.key_file.as_deref().unwrap_or(""),
                flags.ignore_expiration
            ),
            output,
        );
        if verifier.is_none() {
            let initialized = verification::Verifier::new(
                flags.key_file.as_deref(),
                flags.algorithm.as_deref(),
                flags.ignore_expiration,
            )
            .map_err(|err| err.to_string());
            if let Ok(verifier) = &initialized {
                if let Some(warning) = verifier.weak_hmac_key_warning() {
                    printer::print_weak_hmac_key_warning(warning.actual, warning.minimum, output);
                }
            }
            *verifier = Some(initialized);
        }

        let verifier = match verifier.as_ref().expect("verifier state was initialized") {
            Ok(verifier) => verifier,
            Err(message) => {
                printer::print_verification_failure(message, output);
                return EXIT_VERIFICATION_FAIL;
            }
        };
        if let Err(err) = verifier.verify(&parsed) {
            printer::print_verification_failure(&err, output);
            return EXIT_VERIFICATION_FAIL;
        }
        log_verbose(flags, "signature verification succeeded", output);
    }

    if flags.raw_claims {
        match serde_json::to_string_pretty(&parsed.claims) {
            Ok(data) => output.stdout_line(format_args!("{data}")),
            Err(err) => {
                output.stderr_line(format_args!(
                    "Error: failed to encode claims as JSON: {err}"
                ));
                return EXIT_ERROR;
            }
        }
        return EXIT_SUCCESS;
    }

    if !flags.verify_signature {
        printer::print_unverified_notice(flags.quiet, output);
    }

    if flags.header {
        printer::print_header(&parsed.header, output);
    }

    if flags.claims {
        printer::print_claims(&parsed.claims, output);
    }

    if flags.signature {
        printer::print_signature(&parsed.signature, output);
    }

    if flags.expiration {
        expiration::check_expiration(&parsed.claims, output);
    }

    if flags.verify_signature {
        printer::print_verification_success(output);
    }

    EXIT_SUCCESS
}

fn log_verbose_parse(
    flags: &cli::Flags,
    input: &str,
    parsed: &parser::ParsedToken,
    output: &mut output::Output<'_>,
) {
    if !flags.verbose {
        return;
    }

    let trimmed = input.trim();
    if trimmed != parsed.raw {
        log_verbose(
            flags,
            format!(
                "extracted JWT from input ({} bytes -> {} bytes)",
                trimmed.len(),
                parsed.raw.len()
            ),
            output,
        );
    } else {
        log_verbose(
            flags,
            format!("using token ({} bytes)", parsed.raw.len()),
            output,
        );
    }

    let alg = parsed
        .header
        .get("alg")
        .map(ToString::to_string)
        .unwrap_or_else(|| "<missing>".to_string());
    log_verbose(flags, format!("header alg={alg}"), output);
}

fn log_verbose(flags: &cli::Flags, message: impl AsRef<str>, output: &mut output::Output<'_>) {
    if flags.verbose {
        output.stderr_line(format_args!("verbose: {}", message.as_ref()));
    }
}

fn process_from_stdin(
    flags: &cli::Flags,
    explicit: bool,
    verifier: &mut VerifierState,
    output: &mut output::Output<'_>,
) -> i32 {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        if !explicit {
            print_usage_hint(output);
            return EXIT_ERROR;
        }

        if !flags.quiet {
            output.stderr_line(format_args!(
                "Reading token from stdin... (press Ctrl+D when done)"
            ));
        }
    }

    let mut has_token = false;
    let mut exit_code = EXIT_SUCCESS;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                output.stderr_line(format_args!("Error: failed to read stdin: {err}"));
                return EXIT_ERROR;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        has_token = true;
        exit_code = retain_first_failure(exit_code, process_token(line, flags, verifier, output));
    }

    if !has_token {
        output.stderr_line(format_args!("Error: no token provided on stdin"));
        return EXIT_ERROR;
    }

    exit_code
}

fn print_usage_hint(output: &mut output::Output<'_>) {
    output.stderr_text(
        "Error: no token provided\n\n\
         Usage: jwtdebug [options] <token>\n\
                jwtdebug [options] -           # read from stdin\n\
                command | jwtdebug [options]   # read from pipe\n\n\
         Run 'jwtdebug --help' for more information.\n",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn invalid_token_exits_with_invalid_token_code() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut output = output::Output::new(&mut stdout, &mut stderr);
        assert_eq!(
            EXIT_INVALID_TOKEN,
            run_with_args(["not-a-valid-token"], &mut output)
        );
    }

    #[test]
    fn version_exits_successfully() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut output = output::Output::new(&mut stdout, &mut stderr);
        assert_eq!(EXIT_SUCCESS, run_with_args(["--version"], &mut output));
    }

    #[test]
    fn broken_stdout_exits_successfully() {
        let mut stdout = BrokenPipeWriter;
        let mut stderr = Vec::new();
        let mut output = output::Output::new(&mut stdout, &mut stderr);
        let exit_code = run_with_args(["--help"], &mut output);
        let error = output.finish().expect("broken pipe");

        assert_eq!(io::ErrorKind::BrokenPipe, error.kind());
        assert_eq!(EXIT_SUCCESS, final_exit_code(exit_code, Some(&error)));
    }

    #[test]
    fn broken_stderr_exits_successfully() {
        let mut stdout = Vec::new();
        let mut stderr = BrokenPipeWriter;
        let mut output = output::Output::new(&mut stdout, &mut stderr);
        let exit_code = run_with_args(["not-a-valid-token"], &mut output);
        let error = output.finish().expect("broken pipe");

        assert_eq!(io::ErrorKind::BrokenPipe, error.kind());
        assert_eq!(EXIT_SUCCESS, final_exit_code(exit_code, Some(&error)));
    }
}
