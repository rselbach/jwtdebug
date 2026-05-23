use std::fs;

use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use predicates::prelude::*;
use serde_json::json;
use tempfile::NamedTempFile;

fn unsigned_token(claims: serde_json::Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

fn hmac_token(secret: &[u8], claims: serde_json::Value) -> String {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("sign HS256 test token")
}

fn key_file(contents: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("create key file");
    fs::write(file.path(), contents).expect("write key file");
    file
}

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
fn help_matches_go_style_stderr() {
    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .arg("--help")
        .assert()
        .success()
        .stdout("")
        .stderr(predicate::str::contains(
            "Usage: jwtdebug [options] [token]",
        ))
        .stderr(predicate::str::contains("Display:"))
        .stderr(predicate::str::contains("Exit Codes:"));
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

#[test]
fn hmac_verify_success_prints_success_message() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Annie Edison" }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn raw_claims_with_verify_failure_keeps_stdout_empty() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let wrong_secret = b"wrong-secret-key-at-least-32-bytes!!";
    let token = hmac_token(secret, json!({ "sub": "Verified Raw Claims" }));
    let key_file = key_file(wrong_secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--raw-claims",
            "--verify",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains("Signature verification failed"));
}
