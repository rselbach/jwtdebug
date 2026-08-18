use std::ffi::OsString;

use clap::{ArgAction, CommandFactory, Parser, error::ErrorKind};

pub const VERSION: &str = match option_env!("JWTDEBUG_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
pub const COMMIT: &str = match option_env!("JWTDEBUG_COMMIT") {
    Some(commit) => commit,
    None => "unknown",
};
pub const BUILD_DATE: &str = match option_env!("JWTDEBUG_BUILD_DATE") {
    Some(date) => date,
    None => "unknown",
};

const AFTER_HELP: &str = r#"If no token is provided, jwtdebug reads from stdin.

Examples:
  jwtdebug eyJhbGci...              # Decode a token
  echo "Bearer eyJ..." | jwtdebug   # Read from pipe
  pbpaste | jwtdebug                # Decode from the macOS clipboard
  jwtdebug -a token                 # Show all token parts and expiration
  jwtdebug -V -k pub.pem --algorithm RS256 token
                                    # Verify with a trusted algorithm and key
  jwtdebug --raw-claims token | jq  # Pipe claims to jq

Exit codes:
  0  Success
  1  General error
  2  Invalid token format
  3  Signature verification failed

Token inputs are limited to 1 MiB per argument or stdin line.

For more information, see: https://github.com/rselbach/jwtdebug"#;

#[derive(Debug, Parser)]
#[command(
    name = "jwtdebug",
    disable_version_flag = true,
    about = "JWT Debug Tool - Decode and analyze JWT tokens",
    after_help = AFTER_HELP
)]
struct Args {
    #[arg(short = 'H', long, action = ArgAction::SetTrue, help = "show token header")]
    header: bool,

    #[arg(
        short = 'c',
        long,
        default_value_t = true,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        help = "show token claims (payload)"
    )]
    claims: bool,

    #[arg(short = 's', long, action = ArgAction::SetTrue, help = "show token signature")]
    signature: bool,

    #[arg(short = 'a', long = "all", action = ArgAction::SetTrue, help = "show all token parts and info")]
    show_all: bool,

    #[arg(short = 'e', long, action = ArgAction::SetTrue, help = "check token expiration status")]
    expiration: bool,

    #[arg(long = "raw-claims", action = ArgAction::SetTrue, help = "output only raw claims JSON (for piping to jq)")]
    raw_claims: bool,

    #[arg(short = 'V', long = "verify", action = ArgAction::SetTrue, help = "verify token signature (requires --key-file)")]
    verify_signature: bool,

    #[arg(
        long,
        value_name = "algorithm",
        help = "expected signing algorithm for verification"
    )]
    algorithm: Option<String>,

    #[arg(
        short = 'k',
        long = "key-file",
        value_name = "file",
        help = "key file for signature verification"
    )]
    key_file: Option<String>,

    #[arg(long = "ignore-expiration", action = ArgAction::SetTrue, help = "ignore token expiration when verifying")]
    ignore_expiration: bool,

    #[arg(long, action = ArgAction::SetTrue, help = "disable smart extraction (expect exact JWT input)")]
    strict: bool,

    #[arg(long = "version", action = ArgAction::SetTrue, help = "show version information")]
    show_version: bool,

    #[arg(short = 'q', long, action = ArgAction::SetTrue, help = "suppress informational notices")]
    quiet: bool,

    #[arg(short = 'v', long, action = ArgAction::SetTrue, help = "enable verbose output for debugging")]
    verbose: bool,

    #[arg(long = "key", hide = true)]
    deprecated_key: Option<String>,

    #[arg(long = "expiry", hide = true, action = ArgAction::SetTrue)]
    deprecated_expiry: bool,

    #[arg(long = "ignore-exp", hide = true, action = ArgAction::SetTrue)]
    deprecated_ignore_expiration: bool,

    #[arg(value_name = "token")]
    tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flags {
    pub key_file: Option<String>,
    pub algorithm: Option<String>,
    pub header: bool,
    pub claims: bool,
    pub signature: bool,
    pub expiration: bool,
    pub ignore_expiration: bool,
    pub verify_signature: bool,
    pub show_version: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub raw_claims: bool,
    pub strict: bool,
}

pub struct ParsedArgs {
    pub flags: Flags,
    pub tokens: Vec<String>,
    pub warnings: Vec<&'static str>,
}

pub fn parse<I, T>(args: I) -> Result<ParsedArgs, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = Args::try_parse_from(normalize_single_dash_long_flags(args))?;
    if args.algorithm.is_some() && !args.verify_signature {
        return Err(clap::Error::raw(
            ErrorKind::MissingRequiredArgument,
            "--algorithm requires --verify",
        ));
    }

    let mut warnings = Vec::new();
    if args.deprecated_key.is_some() {
        warnings.push("Warning: --key is deprecated, use --key-file");
    }
    if args.deprecated_expiry {
        warnings.push("Warning: --expiry is deprecated, use --expiration");
    }
    if args.deprecated_ignore_expiration {
        warnings.push("Warning: --ignore-exp is deprecated, use --ignore-expiration");
    }

    Ok(ParsedArgs {
        flags: Flags {
            key_file: args.key_file.or(args.deprecated_key),
            algorithm: args.algorithm,
            header: args.header || args.show_all,
            claims: args.claims || args.show_all,
            signature: args.signature || args.show_all,
            expiration: args.expiration || args.deprecated_expiry || args.show_all,
            ignore_expiration: args.ignore_expiration || args.deprecated_ignore_expiration,
            verify_signature: args.verify_signature,
            show_version: args.show_version,
            quiet: args.quiet,
            verbose: args.verbose,
            raw_claims: args.raw_claims,
            strict: args.strict,
        },
        tokens: args.tokens,
        warnings,
    })
}

fn normalize_single_dash_long_flags<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut normalized = vec![OsString::from("jwtdebug")];
    let command = Args::command();
    let long_flags: Vec<&str> = command
        .get_arguments()
        .filter_map(clap::Arg::get_long)
        .collect();
    let mut options_done = false;

    for argument in args {
        let argument = argument.into();
        let Some(text) = argument.to_str() else {
            normalized.push(argument);
            continue;
        };
        if options_done {
            normalized.push(argument);
            continue;
        }
        if text == "--" {
            options_done = true;
            normalized.push(argument);
            continue;
        }
        if text.starts_with("--") || !text.starts_with('-') || text == "-" {
            normalized.push(argument);
            continue;
        }

        let name = text[1..]
            .split_once('=')
            .map_or(&text[1..], |(name, _)| name);
        if long_flags.contains(&name) {
            normalized.push(OsString::from(format!("-{text}")));
        } else {
            normalized.push(argument);
        }
    }

    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supports_all_legacy_argument_forms() {
        let parsed =
            parse(["-all", "-claims=false", "-expiry", "token"]).expect("parse compatible flags");

        assert!(parsed.flags.header);
        assert!(parsed.flags.claims, "--all takes precedence");
        assert!(parsed.flags.signature);
        assert!(parsed.flags.expiration);
        assert_eq!(parsed.tokens, ["token"]);
        assert_eq!(parsed.warnings.len(), 1);
    }

    #[test]
    fn options_can_follow_tokens_and_double_dash_stops_parsing() {
        let parsed =
            parse(["first", "--quiet", "--", "--verbose"]).expect("parse interspersed options");

        assert!(parsed.flags.quiet);
        assert!(!parsed.flags.verbose);
        assert_eq!(parsed.tokens, ["first", "--verbose"]);
    }

    #[test]
    fn current_key_option_wins_over_deprecated_alias() {
        let parsed = parse(["--key-file", "new", "--key", "old"]).expect("parse key options");
        assert_eq!(parsed.flags.key_file.as_deref(), Some("new"));
    }
}
