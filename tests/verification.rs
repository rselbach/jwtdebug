mod common;

use std::fs;

use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use common::*;
use jsonwebtoken::Algorithm;
use p521::ecdsa::SigningKey;
use p521::elliptic_curve::Generate;
use p521::pkcs8::{EncodePublicKey, LineEnding};
use predicates::prelude::*;
use serde_json::json;

#[test]
fn hmac_verify_success_prints_success_message() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Annie Edison" }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn wrong_hmac_secret_reports_an_invalid_signature() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let wrong_secret = b"wrong-secret-key-at-least-32-bytes!!!!!";
    let token = hmac_token(secret, json!({ "sub": "Ben Chang" }));
    let key_file = key_file(wrong_secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "Signature verification failed: signature is invalid",
        ));
}

#[test]
fn trailing_newline_in_hmac_key_file_is_named_in_the_error() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Ben Chang" }));
    let mut written_with_echo = secret.to_vec();
    written_with_echo.push(b'\n');
    let key_file = key_file(&written_with_echo);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("key file ends with a newline"));
}

#[test]
fn pem_backed_algorithms_verify_successfully() {
    for (algorithm, private_key, public_key, subject) in [
        (Algorithm::RS256, RSA_PRIVATE_KEY, RSA_PUBLIC_KEY, "RS256"),
        (Algorithm::PS256, RSA_PRIVATE_KEY, RSA_PUBLIC_KEY, "PS256"),
        (Algorithm::ES256, EC_PRIVATE_KEY, EC_PUBLIC_KEY, "ES256"),
        (Algorithm::EdDSA, ED_PRIVATE_KEY, ED_PUBLIC_KEY, "EdDSA"),
    ] {
        let token = pem_token(algorithm, private_key, json!({ "sub": subject }));
        let key_file = key_file(public_key.as_bytes());

        Command::cargo_bin("jwtdebug")
            .expect("binary exists")
            .args([
                "--verify",
                "--algorithm",
                subject,
                "--key-file",
                key_file.path().to_str().expect("utf-8 path"),
                &token,
            ])
            .assert()
            .success()
            .stdout(predicate::str::contains(subject))
            .stdout(predicate::str::contains("Signature verified successfully"));
    }
}

#[test]
fn verify_without_key_file_exits_3() {
    let token = unsigned_token(json!({ "sub": "Missing Key" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--verify", &token])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "key file not provided (--key-file / -k required)",
        ));
}

#[test]
fn verify_without_expected_algorithm_exits_3() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Missing Expected Algorithm" }));
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
        .code(3)
        .stderr(predicate::str::contains(
            "expected signing algorithm not provided (--algorithm required)",
        ));
}

#[test]
fn missing_key_file_exits_3() {
    let token = unsigned_token(json!({ "sub": "Missing Key File" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            "/tmp/jwtdebug-missing-key-file",
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to open key file"));
}

#[test]
fn directory_key_file_exits_3() {
    let token = unsigned_token(json!({ "sub": "Directory Key File" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            ".",
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("key file must be a regular file"));
}

#[cfg(unix)]
#[test]
fn fifo_key_file_is_rejected_without_blocking() {
    let token = unsigned_token(json!({ "sub": "Greendale Intercom" }));
    let directory = tempfile::tempdir().expect("create temporary directory");
    let fifo = directory.path().join("key.fifo");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("run mkfifo");
    assert!(status.success(), "mkfifo failed with {status}");

    let mut command = Command::cargo_bin("jwtdebug").expect("binary exists");
    command
        .timeout(std::time::Duration::from_secs(2))
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            fifo.to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("key file must be a regular file"));
}

#[test]
fn oversized_key_file_exits_3() {
    let token = unsigned_token(json!({ "sub": "Oversized Key File" }));
    let key_file = key_file(&vec![b'a'; 1024 * 1024 + 1]);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("key file too large"));
}

#[cfg(unix)]
#[test]
fn unreadable_key_file_exits_3() {
    use std::os::unix::fs::PermissionsExt;

    let token = unsigned_token(json!({ "sub": "Unreadable Key File" }));
    let key_file = key_file(b"test-secret-key-at-least-32-bytes-long!");
    fs::set_permissions(key_file.path(), fs::Permissions::from_mode(0o000))
        .expect("make key file unreadable");

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to open key file"));

    fs::set_permissions(key_file.path(), fs::Permissions::from_mode(0o600))
        .expect("restore key file permissions");
}

#[test]
fn asymmetric_public_keys_cannot_be_used_as_hmac_secrets() {
    for public_key in [RSA_PUBLIC_KEY, EC_PUBLIC_KEY, ED_PUBLIC_KEY] {
        let token = hmac_token(
            public_key.as_bytes(),
            json!({ "sub": "Forged Human Being" }),
        );
        let key_file = key_file(public_key.as_bytes());

        Command::cargo_bin("jwtdebug")
            .expect("binary exists")
            .args([
                "--verify",
                "--algorithm",
                "HS256",
                "--key-file",
                key_file.path().to_str().expect("utf-8 path"),
                &token,
            ])
            .assert()
            .code(3)
            .stderr(predicate::str::contains(
                "HMAC key file contains an asymmetric key",
            ));
    }
}

#[test]
fn expected_algorithm_blocks_asymmetric_key_confusion() {
    let token = hmac_token(
        RSA_PUBLIC_KEY.as_bytes(),
        json!({ "sub": "Forged Human Being" }),
    );
    let key_file = key_file(RSA_PUBLIC_KEY.as_bytes());

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "RS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "token signing algorithm HS256 does not match expected algorithm RS256",
        ));
}

#[test]
fn der_encoded_public_keys_cannot_be_used_as_hmac_secrets() {
    for public_key in [RSA_PUBLIC_KEY, EC_PUBLIC_KEY, ED_PUBLIC_KEY] {
        let der = pem_to_der(public_key);
        let token = hmac_token(&der, json!({ "sub": "Forged Human Being" }));
        let key_file = key_file(&der);

        Command::cargo_bin("jwtdebug")
            .expect("binary exists")
            .args([
                "--verify",
                "--algorithm",
                "HS256",
                "--key-file",
                key_file.path().to_str().expect("utf-8 path"),
                &token,
            ])
            .assert()
            .code(3)
            .stderr(predicate::str::contains(
                "HMAC key file contains an asymmetric key",
            ));
    }
}

#[test]
fn short_hmac_key_warns_once_and_verifies_multiple_tokens() {
    let secret = b"too-short";
    let token = hmac_token(secret, json!({ "sub": "Short HMAC Key" }));
    let key_file = key_file(secret);

    let output = Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
            &token,
        ])
        .output()
        .expect("run jwtdebug");

    assert!(output.status.success(), "jwtdebug failed: {output:?}");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert_eq!(1, stderr.matches("Warning: HMAC key is 9 bytes").count());
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert_eq!(2, stdout.matches("Signature verified successfully").count());
}

#[test]
fn jwt_io_sample_token_verifies_with_its_own_secret() {
    // jwt.io's default HS256 example. Its 19-byte secret is the single most
    // common thing anyone pastes at a JWT tool, and a hard minimum key length
    // refused it outright.
    let token = concat!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    );
    let key_file = key_file(b"your-256-bit-secret");

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn token_with_aud_claim_verifies_successfully() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(
        secret,
        json!({ "sub": "Troy Barnes", "aud": "greendale-community-college" }),
    );
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn expired_hmac_token_fails_unless_ignored() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(
        secret,
        json!({ "sub": "Expired HMAC", "exp": past_timestamp() }),
    );
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("token is expired"));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--ignore-expiration",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn maximum_unsigned_exp_verifies_successfully() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Troy Barnes", "exp": u64::MAX }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn unsigned_range_float_exp_verifies_successfully() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Troy Barnes", "exp": 1e19 }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Signature verified successfully"));
}

#[test]
fn string_exp_is_enforced_during_verify() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "String Exp", "exp": "1000000000" }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("token is expired"));
}

#[test]
fn fractional_string_exp_is_enforced_during_verify() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(
        secret,
        json!({ "sub": "Fractional String Exp", "exp": "1000000000.5" }),
    );
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("token is expired"));
}

#[test]
fn string_nbf_is_enforced_during_verify() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "String Nbf", "nbf": "2000000000" }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("token is not valid yet"));
}

#[test]
fn ignore_expiration_still_enforces_nbf() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(
        secret,
        json!({ "sub": "Annie Edison", "exp": 1, "nbf": "2000000000" }),
    );
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--ignore-expiration",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("token is not valid yet"));
}

#[test]
fn malformed_exp_fails_verify() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Bad Exp", "exp": true }));
    let key_file = key_file(secret);

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("invalid exp claim"));
}

#[test]
fn unsupported_algorithm_exits_3() {
    let token = token_with_header(
        json!({ "alg": "none", "typ": "JWT" }),
        json!({ "sub": "Unsupported Algorithm" }),
    );
    let key_file = key_file(b"test-secret-key-at-least-32-bytes-long!");

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "none",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("unexpected signing method: none"));
}

#[test]
fn missing_algorithm_exits_3() {
    let token = token_with_header(
        json!({ "typ": "JWT" }),
        json!({ "sub": "Missing Algorithm" }),
    );
    let key_file = key_file(b"test-secret-key-at-least-32-bytes-long!");

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains(
            "unexpected signing method: <missing>",
        ));
}

#[test]
fn asymmetric_algorithms_route_to_key_parsers() {
    let key_file = key_file(b"not-a-valid-public-key-but-long-enough");

    for algorithm in ["RS256", "PS256", "ES256", "EdDSA"] {
        let token = token_with_header(
            json!({ "alg": algorithm, "typ": "JWT" }),
            json!({ "sub": "Algorithm Routing" }),
        );

        Command::cargo_bin("jwtdebug")
            .expect("binary exists")
            .args([
                "--verify",
                "--algorithm",
                algorithm,
                "--key-file",
                key_file.path().to_str().expect("utf-8 path"),
                &token,
            ])
            .assert()
            .code(3)
            .stderr(predicate::str::contains("Signature verification failed"));
    }
}

#[test]
fn es512_invalid_public_key_reports_parser_error() {
    let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "ES512", "typ": "JWT" }).to_string());
    let claims = URL_SAFE_NO_PAD.encode(json!({ "sub": "ES512 Key Parser" }).to_string());
    let signature = URL_SAFE_NO_PAD.encode(vec![1_u8; 132]);
    let token = format!("{header}.{claims}.{signature}");
    let key_file = key_file(b"not-a-valid-public-key-but-long-enough");

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "ES512",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to parse ES512 public key"));
}

#[test]
fn es512_malformed_signature_reports_signature_error() {
    let token = token_with_header(
        json!({ "alg": "ES512", "typ": "JWT" }),
        json!({ "sub": "ES512 Signature Parser" }),
    );
    let signing_key = SigningKey::generate();
    let public_key = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("encode public key");
    let key_file = key_file(public_key.as_bytes());

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--algorithm",
            "ES512",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to parse ES512 signature"));
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
            "--algorithm",
            "HS256",
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains("Signature verification failed"));
}
