use serde_json::{json, Map, Value};

use crate::output::Output;

pub fn print_header(header: &Map<String, Value>, output: &mut Output<'_>) {
    output.stdout_line(format_args!("HEADER:"));
    output.stdout_line(format_args!(
        "{}",
        serde_json::to_string_pretty(header).expect("header JSON should encode")
    ));
    output.stdout_line(format_args!(""));
}

pub fn print_claims(claims: &Map<String, Value>, output: &mut Output<'_>) {
    output.stdout_line(format_args!("CLAIMS:"));
    output.stdout_line(format_args!(
        "{}",
        serde_json::to_string_pretty(claims).expect("claims JSON should encode")
    ));
    output.stdout_line(format_args!(""));
}

pub fn print_signature(signature: &str, output: &mut Output<'_>) {
    output.stdout_line(format_args!("SIGNATURE:"));
    output.stdout_line(format_args!(
        "{}",
        serde_json::to_string_pretty(&json!({ "raw": signature }))
            .expect("signature JSON should encode")
    ));
    output.stdout_line(format_args!(""));
}

pub fn print_verification_success(output: &mut Output<'_>) {
    output.stdout_line(format_args!("Signature verified successfully"));
}

pub fn print_verification_failure(err: impl std::fmt::Display, output: &mut Output<'_>) {
    output.stderr_line(format_args!("Signature verification failed: {err}"));
}

pub fn print_weak_hmac_key_warning(actual: usize, minimum: usize, output: &mut Output<'_>) {
    output.stderr_line(format_args!(
        "Warning: HMAC key is {actual} bytes; RFC 7518 requires at least {minimum} for this algorithm"
    ));
}

pub fn print_unverified_notice(quiet: bool, output: &mut Output<'_>) {
    if quiet {
        return;
    }

    output.stderr_line(format_args!(
        "Note: claims are unverified. Use --verify --key-file --algorithm to validate."
    ));
}
