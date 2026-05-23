use std::ffi::OsString;

use clap::{ArgAction, Parser};

pub const VERSION: &str = match option_env!("JWTDEBUG_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};
pub const COMMIT: &str = match option_env!("JWTDEBUG_COMMIT") {
    Some(commit) => commit,
    None => "unknown",
};
pub const BUILD_DATE: &str = match option_env!("JWTDEBUG_BUILD_DATE") {
    Some(build_date) => build_date,
    None => "unknown",
};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "jwtdebug",
    disable_help_flag = true,
    disable_version_flag = true,
    about = "JWT Debug Tool - Decode and analyze JWT tokens"
)]
struct Args {
    #[arg(short = 'H', long, action = ArgAction::SetTrue, help = "show token header")]
    header: bool,

    #[arg(short = 'c', long, default_value_t = true, num_args = 0..=1, require_equals = true, default_missing_value = "true", help = "show token claims (payload)")]
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

    #[arg(short = 'h', long = "help", action = ArgAction::SetTrue, help = "show help message")]
    show_help: bool,

    #[arg(short = 'q', long, action = ArgAction::SetTrue, help = "suppress informational notices")]
    quiet: bool,

    #[arg(short = 'v', long, action = ArgAction::SetTrue, help = "enable verbose output for debugging")]
    verbose: bool,

    #[arg(long = "key", hide = true)]
    key_deprecated: Option<String>,

    #[arg(long = "expiry", hide = true, action = ArgAction::SetTrue)]
    expiry_deprecated: bool,

    #[arg(long = "ignore-exp", hide = true, action = ArgAction::SetTrue)]
    ignore_exp_deprecated: bool,

    #[arg(value_name = "token")]
    tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flags {
    pub key_file: Option<String>,
    pub header: bool,
    pub claims: bool,
    pub signature: bool,
    pub expiration: bool,
    pub ignore_expiration: bool,
    pub verify_signature: bool,
    pub show_all: bool,
    pub show_version: bool,
    pub show_help: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub raw_claims: bool,
    pub strict: bool,
}

impl Flags {
    pub fn apply_all_flag(&mut self) {
        if self.show_all {
            self.header = true;
            self.claims = true;
            self.signature = true;
            self.expiration = true;
        }
    }
}

pub fn parse<I, T>(args: I) -> Result<(Flags, Vec<String>), clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let args = normalize_go_style_flags(args);
    let args = Args::try_parse_from(args)?;

    if args.key_deprecated.is_some() {
        eprintln!("Warning: --key is deprecated, use --key-file");
    }
    if args.expiry_deprecated {
        eprintln!("Warning: --expiry is deprecated, use --expiration");
    }
    if args.ignore_exp_deprecated {
        eprintln!("Warning: --ignore-exp is deprecated, use --ignore-expiration");
    }

    let key_file = args.key_file.or(args.key_deprecated);
    let expiration = args.expiration || args.expiry_deprecated;
    let ignore_expiration = args.ignore_expiration || args.ignore_exp_deprecated;

    Ok((
        Flags {
            key_file,
            header: args.header,
            claims: args.claims,
            signature: args.signature,
            expiration,
            ignore_expiration,
            verify_signature: args.verify_signature,
            show_all: args.show_all,
            show_version: args.show_version,
            show_help: args.show_help,
            quiet: args.quiet,
            verbose: args.verbose,
            raw_claims: args.raw_claims,
            strict: args.strict,
        },
        args.tokens,
    ))
}

fn normalize_go_style_flags<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut normalized = vec![OsString::from("jwtdebug")];
    let long_flags = [
        "all",
        "header",
        "claims",
        "signature",
        "expiration",
        "raw-claims",
        "verify",
        "key-file",
        "ignore-expiration",
        "strict",
        "help",
        "version",
        "quiet",
        "verbose",
        "key",
        "expiry",
        "ignore-exp",
    ];

    for arg in args {
        let arg = arg.into();
        let Some(s) = arg.to_str() else {
            normalized.push(arg);
            continue;
        };

        if s.starts_with("--") || !s.starts_with('-') || s == "-" {
            normalized.push(OsString::from(s));
            continue;
        }

        let without_dash = &s[1..];
        let flag_name = without_dash
            .split_once('=')
            .map_or(without_dash, |(name, _)| name);
        if long_flags.contains(&flag_name) {
            normalized.push(OsString::from(format!("-{s}")));
            continue;
        }

        normalized.push(OsString::from(s));
    }

    normalized
}

pub fn print_usage() {
    eprintln!("JWT Debug Tool - Decode and analyze JWT tokens");
    eprintln!();
    eprintln!("Usage: jwtdebug [options] [token]");
    eprintln!("       jwtdebug [options] -           # read from stdin explicitly");
    eprintln!("       command | jwtdebug [options]   # read from pipe");
    eprintln!();
    eprintln!("If no token is provided, jwtdebug reads from stdin.");
    eprintln!();
    eprintln!("  Display:");
    eprintln!("    --header, -H             show token header");
    eprintln!("    --claims, -c             show token claims (payload)");
    eprintln!("    --signature, -s          show token signature");
    eprintln!("    --all, -a                show all token parts and info");
    eprintln!("    --expiration, -e         check token expiration status");
    eprintln!("    --raw-claims             output only raw claims JSON (for piping to jq)");
    eprintln!();
    eprintln!("  Verification:");
    eprintln!("    --verify, -V             verify token signature (requires --key-file)");
    eprintln!("    --key-file, -k <file>    key file for signature verification");
    eprintln!("    --ignore-expiration      ignore token expiration when verifying");
    eprintln!();
    eprintln!("  Input:");
    eprintln!("    --strict                 disable smart extraction (expect exact JWT input)");
    eprintln!();
    eprintln!("  Other:");
    eprintln!("    --help, -h               show help message");
    eprintln!("    --version                show version information");
    eprintln!("    --quiet, -q              suppress informational notices");
    eprintln!("    --verbose, -v            enable verbose output for debugging");
    eprintln!(
        r#"
Examples:
  jwtdebug eyJhbGci...              # Decode a token
  echo "Bearer eyJ..." | jwtdebug   # Read from pipe (strips "Bearer " prefix)
  pbpaste | jwtdebug                # Decode token from clipboard (macOS)
  jwtdebug -a token                 # Show all parts (header, claims, signature, expiry)
  jwtdebug -V -k pub.pem token      # Verify signature with public key
  jwtdebug --raw-claims token | jq  # Pipe claims to jq

Exit Codes:
  0  Success
  1  General error
  2  Invalid token format
  3  Signature verification failed

For more information, see: https://github.com/rselbach/jwtdebug
"#
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_flag_enables_everything() {
        let (mut flags, _) = parse(["--all"]).expect("parse flags");
        flags.apply_all_flag();

        assert!(flags.header);
        assert!(flags.claims);
        assert!(flags.signature);
        assert!(flags.expiration);
    }

    #[test]
    fn claims_can_be_disabled_go_style() {
        let (flags, _) = parse(["-claims=false"]).expect("parse flags");
        assert!(!flags.claims);
    }

    #[test]
    fn deprecated_key_alias_sets_key_file() {
        let (flags, _) = parse(["-key", "somefile"]).expect("parse flags");
        assert_eq!(Some("somefile".to_string()), flags.key_file);
    }
}
