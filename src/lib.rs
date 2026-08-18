mod app;
mod cli;
mod constants;
mod expiration;
mod output;
mod parser;
mod time_claims;
mod verification;

use std::ffi::OsString;
use std::io::{self, BufRead, Write};

pub use constants::{EXIT_ERROR, EXIT_INVALID_TOKEN, EXIT_SUCCESS, EXIT_VERIFICATION_FAIL};

/// Runs jwtdebug with explicit process streams and returns its exit code.
///
/// Keeping the process boundary injectable makes the complete CLI behavior
/// testable without global I/O or environment mutation.
pub fn run<I, T>(
    args: I,
    stdin: &mut dyn BufRead,
    stdin_is_terminal: bool,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let (exit_code, output_errors) = {
        let mut output = output::Output::new(stdout, stderr);
        let exit_code = app::run(args, stdin, stdin_is_terminal, &mut output);
        (exit_code, output.finish())
    };

    if let Some(errors) = output_errors.as_ref()
        && !errors.only_broken_pipes()
    {
        let _ = writeln!(stderr, "Error: failed to write output: {errors}");
    }

    match output_errors {
        None => exit_code,
        Some(errors) if errors.only_broken_pipes() => EXIT_SUCCESS,
        Some(_) => EXIT_ERROR,
    }
}

/// Runs jwtdebug against the current process environment.
pub fn run_env() -> i32 {
    use std::io::IsTerminal;

    let stdin = io::stdin();
    let stdin_is_terminal = stdin.is_terminal();
    let mut stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let stderr = io::stderr();
    let mut stderr = stderr.lock();

    run(
        std::env::args_os().skip(1),
        &mut stdin,
        stdin_is_terminal,
        &mut stdout,
        &mut stderr,
    )
}
