use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use assert_cmd::Command;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use predicates::prelude::*;
use serde_json::json;
use tempfile::NamedTempFile;

const RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCcr2YhHuCGS5aU
URJ/ofsXvbmWZ+yvNJEafC/wa/gSkUO2yRjOBgzXVFwmMzQjd4OGPEGd8CzzuGmU
Hv9LVZHKOsCvO67uogJrhW5PkgxOexcb2B09ukpNahgdJxgO5RV6zd76MiWlUhAs
sxf6x16XqGQ0BWsnf0+4D34+xJv2oTrTsUiwdU4hl7z+Q2qdZj7QF7tLnNLRcPGe
k8H7IJV0UYCkc5UgXd7ExzrFBMnFGTSzeSSBS91Aw/6tSw08byWxmrYVWbrVmYT+
vQfhpDwhB3g7iNZ3u5w58p41V//IymhaxCWHD2gOqMGaspRH4TnpGEm2Ustacp8i
sTMVcY49AgMBAAECggEAHhxdCZ9n8ZcEJJOh9PI5kVnuGPf21cLJ4eecxNzS6yqM
c0uZHzqtbBIztUmgyvIUTg81Yvc9hEbbz1HXqPAUWONKlUJof0aWJXiaduMvx0ND
cR/qmqq6zb7GTI/vQSmII7X9lGJftrIbFqQCRzjaNlXvj8m8ynXeaZZcog5hlJch
etVtXsxNuAE3F77lDEu04hCZAcmsJKxmiuSt172ug6AmOQdckd0dN8wO3jfPQt0/
nwNhcxeaTouX9jp7bGCxBA3oc+pwjAN0AqMxUM4+rPsFdr9FOCxuevz1NUyjL6go
6TG0Wg2bAf8yy6NY0h2sUabYmCJx/Fq+smx8edYqgQKBgQDMil9q2QYOZMLSwtff
RJ7y6gcrwgmnhaM7lu/OVOTyNgC9tvijNaBtjvV9M3nNk7pr5cyd4NkL8+mpw+Xe
rkGG8XNUbfv81Ba5Qk+XDhCeo20QzFuDBrV3KH+jh3ASrClYDF68HivYkLnNFxXh
GHrEtwzVGnpoXYJNwRbSmZ0bwQKBgQDEGtsOFN4MJz3L/1slKZXzXzr4WjswIHJU
Yuay2cJ8z2v93DizEDfQtISUEROuHanmkOXtnu7ho7rI+oqpGHS2sKV5yOLxAXCV
PUMH4bPC/PbEnWop0HaWQclSTQim43bnzxmiXnj3zfltayBLIBBq8cT/2s4mYQVa
x1zz529BfQKBgQCq8J3L2zIvh1A2+fWVt3CrjKCPlmuhIJOJ8pvZsaNhNXarFqZ3
KBM6XLaXexS5lVPAZt35t/dNAPzwDzMmRjWnRFThY8Wrx8hx7ZQ8ptmG6wf0eQWl
3E5+Fk+N6FvmjxFCb5wg1YpJRLKzTy7O3zmC+4Ry+N0CKdwDhXLAcPcXQQKBgHMB
VOoDLt1tvf3+uVMn+jqJ5Kl1MTTeMm5uueC1eCt98VUla1MH9dO9qeqzwRjhaJxA
6bba+Dj3rjjjRaI5J2lkWwb62qyALag4DzF2GdgGRim0L2hqSsF/vzM23hYRW9BC
UkQ4pzScZOTYaE3mdfph4ygxB6jWSS+dr1OSrFp5AoGBAIbOZrsI0gIW/Lxx3284
Re6cTd+IcQ9ZOIOuytE6yWlPtXnr+Rp8wjozWRJLnBo+/MwH8GGEqkKsNkYYWMKl
lJ2UwtR8XTOsNVGSeYptjLeaJUR4PmxeCawftncfVC8Nx1R+WzhY3JAjCiBY9i3p
mH7JosNjCqnxRqyZh3eeZPw5
-----END PRIVATE KEY-----"#;

const RSA_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnK9mIR7ghkuWlFESf6H7
F725lmfsrzSRGnwv8Gv4EpFDtskYzgYM11RcJjM0I3eDhjxBnfAs87hplB7/S1WR
yjrArzuu7qICa4VuT5IMTnsXG9gdPbpKTWoYHScYDuUVes3e+jIlpVIQLLMX+sde
l6hkNAVrJ39PuA9+PsSb9qE607FIsHVOIZe8/kNqnWY+0Be7S5zS0XDxnpPB+yCV
dFGApHOVIF3exMc6xQTJxRk0s3kkgUvdQMP+rUsNPG8lsZq2FVm61ZmE/r0H4aQ8
IQd4O4jWd7ucOfKeNVf/yMpoWsQlhw9oDqjBmrKUR+E56RhJtlLLWnKfIrEzFXGO
PQIDAQAB
-----END PUBLIC KEY-----"#;

const EC_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5DnJ+IO+xX65e+Xv
a+fs1n4SSW28btlalxltGOUytLuhRANCAAReeGwEr7jUfHkn0oCdupx9MTU31KWr
wcBn792fF0LYtEVaXJHSxsrQPdjSBzKsF3jTbItsh3vxds3cukdZp7nj
-----END PRIVATE KEY-----"#;

const EC_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXnhsBK+41Hx5J9KAnbqcfTE1N9Sl
q8HAZ+/dnxdC2LRFWlyR0sbK0D3Y0gcyrBd402yLbId78XbN3LpHWae54w==
-----END PUBLIC KEY-----"#;

const ED_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH2kwYRNLj8oSmGomiH8h5FVRjGjfYsCooSsjVsp/1H4
-----END PRIVATE KEY-----"#;

const ED_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAeaMkyhBdLsQXBPbyR1MhzwoJwi+nhiHbru7IAsnyjss=
-----END PUBLIC KEY-----"#;

fn unsigned_token(claims: serde_json::Value) -> String {
    token_with_header(json!({ "alg": "none", "typ": "JWT" }), claims)
}

fn token_with_header(header: serde_json::Value, claims: serde_json::Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string()),
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

fn pem_token(algorithm: Algorithm, private_key: &str, claims: serde_json::Value) -> String {
    let encoding_key =
        match algorithm {
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => EncodingKey::from_rsa_pem(private_key.as_bytes())
                .expect("parse RSA private test key"),
            Algorithm::ES256 | Algorithm::ES384 => {
                EncodingKey::from_ec_pem(private_key.as_bytes()).expect("parse EC private test key")
            }
            Algorithm::EdDSA => EncodingKey::from_ed_pem(private_key.as_bytes())
                .expect("parse EdDSA private test key"),
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                panic!("PEM token helper does not support HMAC algorithms")
            }
        };

    encode(&Header::new(algorithm), &claims, &encoding_key).expect("sign PEM-backed test token")
}

fn key_file(contents: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("create key file");
    fs::write(file.path(), contents).expect("write key file");
    file
}

fn past_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
        - 3600
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
fn missing_key_file_exits_3() {
    let token = unsigned_token(json!({ "sub": "Missing Key File" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
            "--key-file",
            "/tmp/jwtdebug-missing-key-file",
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to stat key file"));
}

#[test]
fn directory_key_file_exits_3() {
    let token = unsigned_token(json!({ "sub": "Directory Key File" }));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args(["--verify", "--key-file", ".", &token])
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
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to read key file"));

    fs::set_permissions(key_file.path(), fs::Permissions::from_mode(0o600))
        .expect("restore key file permissions");
}

#[test]
fn short_hmac_key_exits_3() {
    let secret = b"test-secret-key-at-least-32-bytes-long!";
    let token = hmac_token(secret, json!({ "sub": "Short HMAC Key" }));
    let key_file = key_file(b"too-short");

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
        .stderr(predicate::str::contains("HMAC key too short"));
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
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("ExpiredSignature"));

    Command::cargo_bin("jwtdebug")
        .expect("binary exists")
        .args([
            "--verify",
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
    let key_file = key_file(b"not-a-valid-public-key-but-long-enough");

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
            "--key-file",
            key_file.path().to_str().expect("utf-8 path"),
            &token,
        ])
        .assert()
        .code(3)
        .stdout("")
        .stderr(predicate::str::contains("Signature verification failed"));
}
