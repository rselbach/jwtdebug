mod cli;
mod constants;
mod expiration;
mod parser;
mod printer;
mod time_claims;
mod verification;

use std::io::{self, BufRead, IsTerminal};

use constants::{EXIT_ERROR, EXIT_INVALID_TOKEN, EXIT_SUCCESS, EXIT_VERIFICATION_FAIL};

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    run_with_args(std::env::args().skip(1))
}

fn run_with_args<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let (flags, positional_args) = match cli::parse(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            // clap's auto help/version are disabled (cli handles them as
            // regular flags), so every parse failure here is a real error.
            eprint!("{err}");
            return EXIT_ERROR;
        }
    };

    if flags.show_help {
        cli::print_usage();
        return EXIT_SUCCESS;
    }

    if flags.show_version {
        print_version(&flags);
        return EXIT_SUCCESS;
    }

    process_input_tokens(&flags, &positional_args)
}

fn print_version(flags: &cli::Flags) {
    println!("jwtdebug version {}", cli::VERSION);
    if flags.verbose || cli::COMMIT != "unknown" {
        println!("  commit:     {}", cli::COMMIT);
        println!("  built:      {}", cli::BUILD_DATE);
    }
}

fn process_input_tokens(flags: &cli::Flags, args: &[String]) -> i32 {
    match args {
        [] => process_from_stdin(flags, false),
        [arg] if arg == "-" => process_from_stdin(flags, true),
        _ => {
            let mut exit_code = EXIT_SUCCESS;
            for token in args {
                exit_code = retain_first_failure(exit_code, process_token(token, flags));
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

fn process_token(input: &str, flags: &cli::Flags) -> i32 {
    let parsed = match parser::resolve_token(input, flags.strict) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("Error: {err}");
            return EXIT_INVALID_TOKEN;
        }
    };

    log_verbose_parse(flags, input, &parsed);

    if flags.verify_signature {
        log_verbose(
            flags,
            format!(
                "verifying signature with key file {:?} (ignore-expiration={})",
                flags.key_file.as_deref().unwrap_or(""),
                flags.ignore_expiration
            ),
        );
        if let Err(err) = verification::verify_token_signature(
            &parsed,
            flags.key_file.as_deref(),
            flags.algorithm.as_deref(),
            flags.ignore_expiration,
        ) {
            printer::print_verification_failure(&err);
            return EXIT_VERIFICATION_FAIL;
        }
        log_verbose(flags, "signature verification succeeded");
    }

    if flags.raw_claims {
        match serde_json::to_string_pretty(&parsed.claims) {
            Ok(data) => println!("{data}"),
            Err(err) => {
                eprintln!("Error: failed to encode claims as JSON: {err}");
                return EXIT_ERROR;
            }
        }
        return EXIT_SUCCESS;
    }

    if !flags.verify_signature {
        printer::print_unverified_notice(flags.quiet);
    }

    if flags.header {
        printer::print_header(&parsed.header);
    }

    if flags.claims {
        printer::print_claims(&parsed.claims);
    }

    if flags.signature {
        printer::print_signature(&parsed.signature);
    }

    if flags.expiration {
        expiration::check_expiration(&parsed.claims);
    }

    if flags.verify_signature {
        printer::print_verification_success();
    }

    EXIT_SUCCESS
}

fn log_verbose_parse(flags: &cli::Flags, input: &str, parsed: &parser::ParsedToken) {
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
        );
    } else {
        log_verbose(flags, format!("using token ({} bytes)", parsed.raw.len()));
    }

    let alg = parsed
        .header
        .get("alg")
        .map(ToString::to_string)
        .unwrap_or_else(|| "<missing>".to_string());
    log_verbose(flags, format!("header alg={alg}"));
}

fn log_verbose(flags: &cli::Flags, message: impl AsRef<str>) {
    if flags.verbose {
        eprintln!("verbose: {}", message.as_ref());
    }
}

fn process_from_stdin(flags: &cli::Flags, explicit: bool) -> i32 {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        if !explicit {
            print_usage_hint();
            return EXIT_ERROR;
        }

        if !flags.quiet {
            eprintln!("Reading token from stdin... (press Ctrl+D when done)");
        }
    }

    let mut has_token = false;
    let mut exit_code = EXIT_SUCCESS;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("Error: failed to read stdin: {err}");
                return EXIT_ERROR;
            }
        };

        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        has_token = true;
        exit_code = retain_first_failure(exit_code, process_token(line, flags));
    }

    if !has_token {
        eprintln!("Error: no token provided on stdin");
        return EXIT_ERROR;
    }

    exit_code
}

fn print_usage_hint() {
    eprintln!("Error: no token provided");
    eprintln!();
    eprintln!("Usage: jwtdebug [options] <token>");
    eprintln!("       jwtdebug [options] -           # read from stdin");
    eprintln!("       command | jwtdebug [options]   # read from pipe");
    eprintln!();
    eprintln!("Run 'jwtdebug --help' for more information.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_token_exits_with_invalid_token_code() {
        assert_eq!(EXIT_INVALID_TOKEN, run_with_args(["not-a-valid-token"]));
    }

    #[test]
    fn version_exits_successfully() {
        assert_eq!(EXIT_SUCCESS, run_with_args(["--version"]));
    }
}
