use std::io::{self, Cursor, Write};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac as _};
use serde_json::{Value, json};
use sha2::Sha256;
use tempfile::NamedTempFile;

#[derive(Debug)]
struct Result {
    code: i32,
    stdout: String,
    stderr: String,
}

fn execute(args: &[&str], stdin: &str) -> Result {
    let mut stdin = Cursor::new(stdin.as_bytes());
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = jwtdebug::run(args, &mut stdin, false, &mut stdout, &mut stderr);
    Result {
        code,
        stdout: String::from_utf8(stdout).expect("UTF-8 stdout"),
        stderr: String::from_utf8(stderr).expect("UTF-8 stderr"),
    }
}

fn token(header: Value, claims: Value, signature: &[u8]) -> String {
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

fn unsigned_token(subject: &str) -> String {
    token(
        json!({ "alg": "none", "typ": "JWT" }),
        json!({ "sub": subject }),
        &[],
    )
}

fn hmac_token(secret: &[u8], claims: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "HS256", "typ": "JWT" }).to_string());
    let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signing_input = format!("{header}.{claims}");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
    mac.update(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

fn key_file(data: &[u8]) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temporary key file");
    file.write_all(data).expect("write key file");
    file.flush().expect("flush key file");
    file
}

#[test]
fn display_modes_and_unverified_notice_match_the_cli_contract() {
    let token = unsigned_token("Abed Nadir");

    let default = execute(&[&token], "");
    assert_eq!(default.code, 0);
    assert!(default.stdout.contains("CLAIMS:"));
    assert!(default.stdout.contains("Abed Nadir"));
    assert!(!default.stdout.contains("HEADER:"));
    assert!(default.stderr.contains("claims are unverified"));

    let all = execute(&["--quiet", "--all", &token], "");
    for block in ["HEADER:", "CLAIMS:", "SIGNATURE:", "EXPIRATION:"] {
        assert!(all.stdout.contains(block), "missing {block}: {all:?}");
    }
    assert!(all.stderr.is_empty());

    let raw = execute(&["--raw-claims", &token], "");
    assert_eq!(raw.code, 0);
    assert!(!raw.stdout.contains("CLAIMS:"));
    assert!(raw.stderr.is_empty());
    serde_json::from_str::<Value>(&raw.stdout).expect("raw claims are JSON");
}

#[test]
fn smart_extraction_and_strict_mode_handle_wrapped_tokens() {
    let token = unsigned_token("Pierce Hawthorne");
    for wrapped in [
        format!("Bearer {token}"),
        format!("Set-Cookie: session={token}; HttpOnly"),
        format!(r#"{{"access_token":"{token}"}}"#),
    ] {
        let result = execute(&["--quiet", &wrapped], "");
        assert_eq!(result.code, 0, "{result:?}");
        assert!(result.stdout.contains("Pierce Hawthorne"));
    }

    assert_eq!(
        execute(&["--strict", &format!("Bearer {token}")], "").code,
        2
    );
}

#[test]
fn every_input_is_processed_and_the_first_failure_wins() {
    let first = unsigned_token("First Token");
    let last = unsigned_token("Last Token");
    let result = execute(&["--quiet", &first, "not-a-token", &last], "");
    assert_eq!(result.code, 2);
    assert!(result.stdout.contains("First Token"));
    assert!(result.stdout.contains("Last Token"));

    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let signed = hmac_token(secret, json!({ "sub": "Signed Token" }));
    let wrong_key = key_file(b"wrong-secret-key-at-least-32-bytes!!!!!");
    let result = execute(
        &[
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            wrong_key.path().to_str().expect("UTF-8 path"),
            "not-a-token",
            &signed,
        ],
        "",
    );
    assert_eq!(result.code, 2);
    assert!(result.stderr.contains("invalid token format"));
    assert!(result.stderr.contains("signature is invalid"));
}

#[test]
fn stdin_marker_is_ordered_and_may_only_appear_once() {
    let argument = unsigned_token("Argument Token");
    let piped = unsigned_token("Stdin Token");
    let result = execute(&["--quiet", &argument, "-"], &format!("{piped}\n"));
    assert_eq!(result.code, 0);
    assert!(result.stdout.contains("Argument Token"));
    assert!(result.stdout.contains("Stdin Token"));

    let duplicate = execute(&["--quiet", "-", "-"], &format!("{piped}\n"));
    assert_eq!(duplicate.code, 1);
    assert_eq!(duplicate.stdout.matches("Stdin Token").count(), 1);
    assert!(duplicate.stderr.contains("may only be specified once"));
}

#[test]
fn oversized_stdin_lines_are_drained_before_processing_the_next_token() {
    let valid = unsigned_token("After Oversized Input");
    let oversized = "x".repeat(1024 * 1024 + 1);
    let result = execute(&["--quiet"], &format!("{oversized}\n{valid}\n"));
    assert_eq!(result.code, 2);
    assert!(result.stderr.contains("exceeds maximum size"));
    assert!(result.stdout.contains("After Oversized Input"));
}

#[test]
fn help_version_and_argument_errors_use_the_expected_streams() {
    for help in ["--help", "-help", "-h"] {
        let result = execute(&[help], "");
        assert_eq!(result.code, 0);
        assert!(result.stderr.is_empty());
        assert!(
            result
                .stdout
                .contains("Usage: jwtdebug [OPTIONS] [token]...")
        );
        assert!(result.stdout.contains("Exit codes:"));
    }

    let version = execute(&["--version"], "");
    assert_eq!(version.code, 0);
    assert!(version.stdout.starts_with("jwtdebug version "));

    let error = execute(&["--algorithm", "HS256"], "");
    assert_eq!(error.code, 1);
    assert!(error.stderr.contains("--algorithm requires --verify"));
}

#[test]
fn hmac_verification_succeeds_warns_once_and_fails_closed() {
    let secret = b"too-short";
    let signed = hmac_token(secret, json!({ "sub": "Verified Claims" }));
    let key = key_file(secret);
    let key = key.path().to_str().expect("UTF-8 path");
    let result = execute(
        &[
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key,
            &signed,
            &signed,
        ],
        "",
    );
    assert_eq!(result.code, 0, "{result:?}");
    assert_eq!(result.stderr.matches("Warning: HMAC key").count(), 1);
    assert_eq!(
        result
            .stdout
            .matches("Signature verified successfully")
            .count(),
        2
    );

    let wrong = key_file(b"wrong-secret-key-at-least-32-bytes!!");
    let failure = execute(
        &[
            "--raw-claims",
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            wrong.path().to_str().expect("UTF-8 path"),
            &signed,
        ],
        "",
    );
    assert_eq!(failure.code, 3);
    assert!(failure.stdout.is_empty());
    assert!(failure.stderr.contains("signature is invalid"));
}

#[test]
fn hmac_key_newlines_are_preserved_and_explained_on_failure() {
    let secret = b"Greendale Community College secret\n";
    let key = key_file(secret);
    for (signing_secret, want_code) in [(secret.as_slice(), 0), (secret.trim_ascii_end(), 3)] {
        let signed = hmac_token(signing_secret, json!({ "sub": "Troy Barnes" }));
        let result = execute(
            &[
                "--raw-claims",
                "--verify",
                "--algorithm",
                "HS256",
                "--key-file",
                key.path().to_str().expect("UTF-8 path"),
                &signed,
            ],
            "",
        );
        assert_eq!(result.code, want_code, "{result:?}");
        if want_code == 0 {
            assert!(result.stdout.contains("Troy Barnes"));
            assert!(result.stderr.is_empty());
        } else {
            assert!(result.stdout.is_empty());
            assert!(result.stderr.contains("key file ends with a newline"));
        }
    }
}

#[test]
fn verification_configuration_errors_exit_three() {
    let token = unsigned_token("Missing Configuration");
    let key = key_file(b"test-secret-key-at-least-32-bytes-long!");
    let key = key.path().to_str().expect("UTF-8 path");

    let missing_key = execute(&["--verify", &token], "");
    assert_eq!(missing_key.code, 3);
    assert!(missing_key.stderr.contains("key file not provided"));

    let missing_algorithm = execute(&["--verify", "--key-file", key, &token], "");
    assert_eq!(missing_algorithm.code, 3);
    assert!(
        missing_algorithm
            .stderr
            .contains("expected signing algorithm")
    );

    let unsupported = execute(
        &["--verify", "--algorithm", "none", "--key-file", key, &token],
        "",
    );
    assert_eq!(unsupported.code, 3);
    assert!(
        unsupported
            .stderr
            .contains("unexpected signing method: none")
    );
}

#[test]
fn diagnostics_escape_terminal_control_sequences() {
    let unsafe_text = "\u{1b}]0;Greendale\u{7}";
    let invalid = execute(&[&format!("{unsafe_text}-invalid")], "");
    assert_eq!(invalid.code, 2);
    assert!(invalid.stderr.contains(r"\u{1b}]0;Greendale\u{7}"));
    assert!(!invalid.stderr.contains(['\u{1b}', '\u{7}']));

    let key = key_file(b"test-secret-key-at-least-32-bytes-long!");
    let mismatched = token(json!({ "alg": unsafe_text }), json!({}), &[]);
    let result = execute(
        &[
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key.path().to_str().expect("UTF-8 path"),
            &mismatched,
        ],
        "",
    );
    assert_eq!(result.code, 3);
    assert!(result.stderr.contains(r"\u{1b}]0;Greendale\u{7}"));
    assert!(!result.stderr.contains(['\u{1b}', '\u{7}']));
}

struct ErrorWriter(io::ErrorKind);

impl Write for ErrorWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(self.0, "write failed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn output_failures_are_independent_and_broken_pipes_exit_successfully() {
    let token = unsigned_token("Output Failure");
    let mut stdin = Cursor::new([]);
    let mut stdout = ErrorWriter(io::ErrorKind::Other);
    let mut stderr = Vec::new();
    let code = jwtdebug::run([&token], &mut stdin, false, &mut stdout, &mut stderr);
    assert_eq!(code, 1);
    assert!(
        String::from_utf8(stderr)
            .expect("UTF-8")
            .contains("claims are unverified")
    );

    let mut stdin = Cursor::new([]);
    let mut stdout = ErrorWriter(io::ErrorKind::BrokenPipe);
    let mut stderr = Vec::new();
    let code = jwtdebug::run(["--help"], &mut stdin, false, &mut stdout, &mut stderr);
    assert_eq!(code, 0);
    assert!(stderr.is_empty());
}
