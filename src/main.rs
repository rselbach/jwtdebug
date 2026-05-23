mod cli;
mod constants;
mod expiration;
mod parser;
mod printer;
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
    let (mut flags, positional_args) = match cli::parse(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprint!("{err}");
            return if err.use_stderr() {
                EXIT_ERROR
            } else {
                EXIT_SUCCESS
            };
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

    flags.apply_all_flag();
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
            for token in args {
                let token = parser::normalize_token_string(token, flags.strict);
                let exit_code = process_token(&token, flags);
                if exit_code != EXIT_SUCCESS {
                    return exit_code;
                }
            }
            EXIT_SUCCESS
        }
    }
}

fn process_token(token: &str, flags: &cli::Flags) -> i32 {
    let parsed = match parser::parse_token(token) {
        Ok(parsed) => parsed,
        Err(err) => {
            eprintln!("Error: {err}");
            return EXIT_INVALID_TOKEN;
        }
    };

    if flags.verify_signature {
        if let Err(err) = verification::verify_token_signature(
            token,
            flags.key_file.as_deref(),
            flags.ignore_expiration,
        ) {
            printer::print_verification_failure(&err);
            return EXIT_VERIFICATION_FAIL;
        }
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
        printer::print_signature(&parsed.parts[2]);
    }

    if flags.expiration {
        expiration::check_expiration(&parsed.claims);
    }

    if flags.verify_signature {
        printer::print_verification_success();
    }

    EXIT_SUCCESS
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
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                eprintln!("Error: failed to read stdin: {err}");
                return EXIT_ERROR;
            }
        };

        let line = parser::normalize_token_string(&line, flags.strict);
        if line.is_empty() {
            continue;
        }

        has_token = true;
        let exit_code = process_token(&line, flags);
        if exit_code != EXIT_SUCCESS {
            return exit_code;
        }
    }

    if !has_token {
        eprintln!("Error: no token provided on stdin");
        return EXIT_ERROR;
    }

    EXIT_SUCCESS
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
