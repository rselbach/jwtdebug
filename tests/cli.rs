mod common;

use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use predicates::prelude::*;
use serde_json::json;

#[test]
fn invalid_token_exits_2() {
    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .arg("not-a-valid-token")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid token format"));
}

#[test]
fn invalid_signature_encoding_exits_2() {
    let token = format!(
        "{}.{}.@@@",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(r#"{"sub":"Annie Edison"}"#)
    );

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .arg(token)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("failed to decode token signature"));
}

#[test]
fn header_flag_prints_header_block() {
    let token = unsigned_token(json!({ "sub": "Header Test" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--header", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("HEADER:"))
        .stdout(predicate::str::contains(r#""alg": "none""#));
}

#[test]
fn signature_flag_prints_raw_signature_block() {
    let token = format!(
        "{}.{}.c2lnbmF0dXJl",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(r#"{"sub":"Signature Test"}"#)
    );

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--signature", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("SIGNATURE:"))
        .stdout(predicate::str::contains(r#""raw": "c2lnbmF0dXJl""#));
}

#[test]
fn quiet_suppresses_unverified_notice() {
    let token = unsigned_token(json!({ "sub": "Quiet Test" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--quiet", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("CLAIMS:"))
        .stderr("");
}

#[test]
fn verbose_logs_parse_and_verify_diagnostics_to_stderr() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Verbose Test" }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verbose",
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &format!("Bearer {token}"),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "verbose: extracted JWT from input",
        ))
        .stderr(predicate::str::contains("verbose: header alg="))
        .stderr(predicate::str::contains(
            "verbose: verifying signature with key file",
        ))
        .stderr(predicate::str::contains(
            "verbose: signature verification succeeded",
        ))
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn expiration_report_accepts_float_numeric_dates() {
    let token = unsigned_token(json!({ "sub": "Float Exp", "exp": 1_000_000_000.0 }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--expiration", "--claims=false", "--quiet", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("Token expired at"))
        .stdout(predicate::str::contains("seconds ago"));
}

#[test]
fn expiration_report_accepts_maximum_unsigned_timestamp() {
    let token = unsigned_token(json!({
        "sub": "Troy Barnes",
        "exp": u64::MAX,
    }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--expiration", "--claims=false", "--quiet", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Token expires at 18446744073709551615",
        ));
}

#[test]
fn expiration_report_handles_minimum_timestamp() {
    let token = unsigned_token(json!({
        "sub": "Pierce Hawthorne",
        "exp": i64::MIN,
        "nbf": i64::MIN,
        "iat": i64::MIN,
    }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--expiration", "--claims=false", "--quiet", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Token expired at -9223372036854775808",
        ))
        .stdout(predicate::str::contains(
            "Token valid since -9223372036854775808",
        ))
        .stdout(predicate::str::contains("Issued at: -9223372036854775808"));
}

#[test]
fn expiration_report_states_future_iat_as_time_remaining() {
    let token = unsigned_token(json!({ "sub": "Craig Pelton", "iat": 4_102_444_800_u64 }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--expiration", "--claims=false", "--quiet", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("Issued at:"))
        .stdout(predicate::str::contains("seconds from now"))
        .stdout(predicate::str::contains("seconds ago").not());
}

#[test]
fn expiration_report_uses_utc() {
    for (timestamp, want) in [
        (1_700_000_000_i64, "2023-11-14T22:13:20Z"),
        (1_690_000_000, "2023-07-22T04:26:40Z"),
    ] {
        let token = unsigned_token(json!({ "sub": "Jeff Winger", "iat": timestamp }));

        Command::cargo_bin("jwtdebug")
            .expect("binary exists")
            .args(["--expiration", "--claims=false", "--quiet", &token])
            .assert()
            .success()
            .stdout(predicate::str::contains(want));
    }
}

#[test]
fn multiple_token_arguments_are_processed_in_order() {
    let first = unsigned_token(json!({ "sub": "First Token" }));
    let second = unsigned_token(json!({ "sub": "Second Token" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([&first, &second])
        .assert()
        .success()
        .stdout(predicate::str::contains("First Token"))
        .stdout(predicate::str::contains("Second Token"));
}

#[test]
fn every_token_argument_is_processed_despite_failures() {
    let first = unsigned_token(json!({ "sub": "First Token" }));
    let last = unsigned_token(json!({ "sub": "Last Token" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([first.as_str(), "not-a-valid-token", last.as_str()])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("First Token"))
        .stdout(predicate::str::contains("Last Token"))
        .stderr(predicate::str::contains("invalid token format"));
}

#[test]
fn every_stdin_line_is_processed_despite_failures() {
    let first = unsigned_token(json!({ "sub": "First Token" }));
    let last = unsigned_token(json!({ "sub": "Last Token" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .write_stdin(format!("{first}\nnot-a-valid-token\n{last}\n"))
        .assert()
        .code(2)
        .stdout(predicate::str::contains("First Token"))
        .stdout(predicate::str::contains("Last Token"));
}

#[test]
fn the_first_failure_sets_the_exit_code() {
    // An unparseable token (2) ahead of a verification failure (3). Those
    // codes name different problems rather than different severities, so the
    // first one is reported rather than the last or the larger.
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let wrong_secret = b"wrong-secret-key-at-least-32-bytes!!!!!";
    let token = hmac_token(secret, json!({ "sub": "Annie Edison" }));
    let key_file = key_file(wrong_secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            "not-a-valid-token",
            token.as_str(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid token format"))
        .stderr(predicate::str::contains("signature is invalid"));
}

#[test]
fn piped_stdin_decodes_token() {
    let token = unsigned_token(json!({ "sub": "Pipe Test" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .write_stdin(format!("{token}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Pipe Test"));
}

#[test]
fn explicit_stdin_dash_decodes_token() {
    let token = unsigned_token(json!({ "sub": "Dash Stdin Test" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .arg("-")
        .write_stdin(format!("{token}\n"))
        .assert()
        .success()
        .stdout(predicate::str::contains("Dash Stdin Test"));
}

#[test]
fn empty_piped_stdin_is_general_error() {
    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .write_stdin("")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "Error: no token provided on stdin",
        ));
}

#[test]
fn help_goes_to_stdout() {
    for flag in ["--help", "-help"] {
        Command::cargo_bin("jwtdebug")
            .expect("binary exists")
            .arg(flag)
            .assert()
            .success()
            .stderr("")
            .stdout(predicate::str::contains(
                "Usage: jwtdebug [OPTIONS] [token]...",
            ))
            .stdout(predicate::str::contains("Options:"))
            .stdout(predicate::str::contains("--algorithm <algorithm>"))
            .stdout(predicate::str::contains("Exit codes:"));
    }
}

#[test]
fn single_dash_long_all_flag_is_supported() {
    let token = unsigned_token(json!({ "sub": "Go Style All" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["-all", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("HEADER:"))
        .stdout(predicate::str::contains("CLAIMS:"))
        .stdout(predicate::str::contains("SIGNATURE:"))
        .stdout(predicate::str::contains("EXPIRATION:"));
}

#[test]
fn deprecated_key_alias_warns_and_verifies() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Deprecated Key" }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "-key",
            key_file.path().to_str().expect("utf-8 path"),
            "--verify",
            "--algorithm",
            "HS256",
            &token,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: --key is deprecated, use --key-file",
        ))
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn deprecated_expiry_alias_warns_and_reports_expiration() {
    let token = unsigned_token(json!({ "sub": "Deprecated Expiry" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["-expiry", &token])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: --expiry is deprecated, use --expiration",
        ))
        .stdout(predicate::str::contains("EXPIRATION:"));
}

#[test]
fn deprecated_ignore_exp_alias_warns_and_ignores_expiration() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(
        secret,
        json!({ "sub": "Expired HMAC", "exp": past_timestamp() }),
    );
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "-ignore-exp",
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Warning: --ignore-exp is deprecated, use --ignore-expiration",
        ))
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn raw_claims_is_machine_readable_stdout() {
    let token = unsigned_token(json!({ "sub": "Abed Nadir" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--raw-claims", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""sub": "Abed Nadir""#))
        .stderr("");
}

#[test]
fn claims_prints_unverified_notice_to_stderr() {
    let token = unsigned_token(json!({ "sub": "Troy Barnes" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--claims", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("CLAIMS:"))
        .stdout(predicate::str::contains("Troy Barnes"))
        .stderr(predicate::str::contains("Note: claims are unverified"));
}

#[test]
fn all_prints_header_claims_signature_and_expiration() {
    let token = unsigned_token(json!({ "sub": "Britta Perry" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--all", &token])
        .assert()
        .success()
        .stdout(predicate::str::contains("HEADER:"))
        .stdout(predicate::str::contains("CLAIMS:"))
        .stdout(predicate::str::contains("SIGNATURE:"))
        .stdout(predicate::str::contains("EXPIRATION:"));
}

#[test]
fn smart_extraction_accepts_bearer_input() {
    let token = unsigned_token(json!({ "sub": "Pierce Hawthorne" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--claims", &format!("Bearer {token}")])
        .assert()
        .success()
        .stdout(predicate::str::contains("Pierce Hawthorne"));
}

#[test]
fn strict_mode_rejects_bearer_input() {
    let token = unsigned_token(json!({ "sub": "Shirley Bennett" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--strict", &format!("Bearer {token}")])
        .assert()
        .code(2);
}
