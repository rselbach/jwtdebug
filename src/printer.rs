use serde_json::{json, Map, Value};

pub fn print_header(header: &Map<String, Value>) {
    println!("HEADER:");
    println!(
        "{}",
        serde_json::to_string_pretty(header).expect("header JSON should encode")
    );
    println!();
}

pub fn print_claims(claims: &Map<String, Value>) {
    println!("CLAIMS:");
    println!(
        "{}",
        serde_json::to_string_pretty(claims).expect("claims JSON should encode")
    );
    println!();
}

pub fn print_signature(signature: &str) {
    println!("SIGNATURE:");
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({ "raw": signature }))
            .expect("signature JSON should encode")
    );
    println!();
}

pub fn print_verification_success() {
    println!("Signature verified successfully");
}

pub fn print_verification_failure(err: &dyn std::error::Error) {
    eprintln!("Signature verification failed: {err}");
}

pub fn print_unverified_notice(quiet: bool) {
    if quiet {
        return;
    }

    eprintln!("Note: claims are unverified. Use --verify --key-file to validate.");
}
