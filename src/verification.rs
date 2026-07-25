use std::fs;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use p521::ecdsa::signature::Verifier;
use p521::ecdsa::{Signature, VerifyingKey};
use p521::pkcs8::DecodePublicKey;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::constants::MAX_FILE_SIZE_BYTES;
use crate::parser::ParsedToken;
use crate::time_claims::{classify_time_claim, TimeClaim};

// Clock-skew tolerance for exp/nbf, matching jsonwebtoken's historical default
// so every algorithm shares the same temporal policy.
const LEEWAY_SECONDS: i64 = 60;

const MIN_HMAC_KEY_LEN_HS256: usize = 32;
const MIN_HMAC_KEY_LEN_HS384: usize = 48;
const MIN_HMAC_KEY_LEN_HS512: usize = 64;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("key file not provided (--key-file / -k required)")]
    MissingKeyFile,

    #[error("failed to stat key file: {0}")]
    StatKeyFile(#[source] std::io::Error),

    #[error("key file must be a regular file")]
    KeyFileNotRegular,

    #[error("key file too large (max {MAX_FILE_SIZE_BYTES} bytes)")]
    KeyFileTooLarge,

    #[error("failed to read key file: {0}")]
    ReadKeyFile(#[source] std::io::Error),

    #[error("HMAC key file contains an asymmetric key")]
    HmacKeyIsAsymmetric,

    #[error("HMAC key too short: {actual} bytes (minimum {minimum} bytes)")]
    HmacKeyTooShort { actual: usize, minimum: usize },

    #[error("unexpected signing method: {0}")]
    UnexpectedAlgorithm(String),

    #[error("failed to decode token signature: {0}")]
    DecodeSignature(#[source] base64::DecodeError),

    #[error("key file is not valid UTF-8: {0}")]
    KeyFileNotUtf8(#[source] std::str::Utf8Error),

    #[error("failed to parse ES512 public key: {0}")]
    Es512Key(#[source] p521::pkcs8::spki::Error),

    #[error("failed to parse ES512 signature: {0}")]
    Es512Signature(#[source] p521::ecdsa::Error),

    #[error("signature is invalid")]
    SignatureInvalid,

    #[error("token is expired")]
    TokenExpired,

    #[error("token is not valid yet")]
    TokenNotValidYet,

    #[error("invalid {claim} claim: {value}")]
    InvalidTimeClaim { claim: &'static str, value: String },

    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub fn verify_token_signature(
    parsed: &ParsedToken,
    key_file: Option<&str>,
    ignore_expiration: bool,
) -> Result<(), VerificationError> {
    let key_file = key_file
        .filter(|key_file| !key_file.is_empty())
        .ok_or(VerificationError::MissingKeyFile)?;

    let metadata = fs::metadata(key_file).map_err(VerificationError::StatKeyFile)?;
    if !metadata.is_file() {
        return Err(VerificationError::KeyFileNotRegular);
    }
    if metadata.len() > MAX_FILE_SIZE_BYTES {
        return Err(VerificationError::KeyFileTooLarge);
    }

    let key_data = fs::read(key_file).map_err(VerificationError::ReadKeyFile)?;
    let algorithm_name = parsed
        .header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or_else(|| VerificationError::UnexpectedAlgorithm("<missing>".to_string()))?;
    if algorithm_name == "ES512" {
        return verify_es512(parsed, &key_data, ignore_expiration);
    }

    let algorithm = Algorithm::from_str(algorithm_name)
        .map_err(|_| VerificationError::UnexpectedAlgorithm(algorithm_name.to_string()))?;
    let key = decoding_key(algorithm, &key_data)?;

    let mut validation = Validation::new(algorithm);
    validation.required_spec_claims.clear();
    // jsonwebtoken rejects any token carrying an aud claim unless an expected
    // audience is configured; as a debug tool we accept any audience.
    validation.validate_aud = false;
    // Temporal checks run through validate_time_claims so string/float/malformed
    // exp and nbf values share one fail-closed policy with the ES512 path.
    validation.validate_exp = false;
    validation.validate_nbf = false;

    decode::<Value>(&parsed.raw, &key, &validation)?;
    if !ignore_expiration {
        validate_time_claims(&parsed.claims)?;
    }
    Ok(())
}

fn decoding_key(algorithm: Algorithm, key_data: &[u8]) -> Result<DecodingKey, VerificationError> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if is_asymmetric_key(key_data) {
                return Err(VerificationError::HmacKeyIsAsymmetric);
            }

            let min_len = match algorithm {
                Algorithm::HS256 => MIN_HMAC_KEY_LEN_HS256,
                Algorithm::HS384 => MIN_HMAC_KEY_LEN_HS384,
                _ => MIN_HMAC_KEY_LEN_HS512,
            };
            if key_data.len() < min_len {
                return Err(VerificationError::HmacKeyTooShort {
                    actual: key_data.len(),
                    minimum: min_len,
                });
            }
            Ok(DecodingKey::from_secret(key_data))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => Ok(DecodingKey::from_rsa_pem(key_data)?),
        Algorithm::ES256 | Algorithm::ES384 => Ok(DecodingKey::from_ec_pem(key_data)?),
        Algorithm::EdDSA => Ok(DecodingKey::from_ed_pem(key_data)?),
    }
}

fn is_asymmetric_key(key_data: &[u8]) -> bool {
    DecodingKey::from_rsa_pem(key_data).is_ok()
        || DecodingKey::from_ec_pem(key_data).is_ok()
        || DecodingKey::from_ed_pem(key_data).is_ok()
        || std::str::from_utf8(key_data)
            .is_ok_and(|key_pem| VerifyingKey::from_public_key_pem(key_pem).is_ok())
}

fn verify_es512(
    parsed: &ParsedToken,
    key_data: &[u8],
    ignore_expiration: bool,
) -> Result<(), VerificationError> {
    let signature = URL_SAFE_NO_PAD
        .decode(&parsed.signature)
        .map_err(VerificationError::DecodeSignature)?;
    let signature = Signature::from_slice(&signature).map_err(VerificationError::Es512Signature)?;
    let key_pem = std::str::from_utf8(key_data).map_err(VerificationError::KeyFileNotUtf8)?;
    let verifying_key =
        VerifyingKey::from_public_key_pem(key_pem).map_err(VerificationError::Es512Key)?;

    let signing_input = parsed
        .raw
        .rsplit_once('.')
        .map(|(input, _)| input)
        .expect("ParsedToken raw always has three segments");
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| VerificationError::SignatureInvalid)?;

    if !ignore_expiration {
        validate_time_claims(&parsed.claims)?;
    }

    Ok(())
}

fn validate_time_claims(claims: &Map<String, Value>) -> Result<(), VerificationError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64);

    validate_time_claims_at(claims, now)
}

fn validate_time_claims_at(claims: &Map<String, Value>, now: i64) -> Result<(), VerificationError> {
    match classify_time_claim(claims, "exp") {
        TimeClaim::Absent => {}
        TimeClaim::Invalid => {
            return Err(VerificationError::InvalidTimeClaim {
                claim: "exp",
                value: claims
                    .get("exp")
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "<missing>".to_string()),
            });
        }
        TimeClaim::Valid(exp) if exp.is_before(now.saturating_sub(LEEWAY_SECONDS)) => {
            return Err(VerificationError::TokenExpired);
        }
        TimeClaim::Valid(_) => {}
    }

    match classify_time_claim(claims, "nbf") {
        TimeClaim::Absent => {}
        TimeClaim::Invalid => {
            return Err(VerificationError::InvalidTimeClaim {
                claim: "nbf",
                value: claims
                    .get("nbf")
                    .map(ToString::to_string)
                    .unwrap_or_else(|| "<missing>".to_string()),
            });
        }
        TimeClaim::Valid(nbf) if nbf.is_after(now.saturating_add(LEEWAY_SECONDS)) => {
            return Err(VerificationError::TokenNotValidYet);
        }
        TimeClaim::Valid(_) => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use p521::ecdsa::signature::Signer;
    use p521::ecdsa::{Signature, SigningKey};
    use p521::elliptic_curve::Generate;
    use p521::pkcs8::{EncodePublicKey, LineEnding};
    use serde_json::json;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::parser;

    #[test]
    fn rejects_expired_fractional_numeric_date() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        let claims = json!({ "exp": now as f64 - 3600.5 });

        let err = validate_time_claims(claims.as_object().expect("claims object"))
            .expect_err("expired token");

        assert!(matches!(err, VerificationError::TokenExpired));
    }

    #[test]
    fn rejects_future_fractional_numeric_date() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        let claims = json!({ "nbf": now as f64 + 3600.5 });

        let err = validate_time_claims(claims.as_object().expect("claims object"))
            .expect_err("token not valid yet");

        assert!(matches!(err, VerificationError::TokenNotValidYet));
    }

    #[test]
    fn enforces_fractional_numeric_dates_at_leeway_boundary() {
        let now = 1_700_000_000;
        let expired = json!({ "exp": 1_699_999_939.6 });
        let err = validate_time_claims_at(expired.as_object().expect("claims object"), now)
            .expect_err("fractional exp is below the leeway boundary");
        assert!(matches!(err, VerificationError::TokenExpired));

        let immature = json!({ "nbf": 1_700_000_060.4 });
        let err = validate_time_claims_at(immature.as_object().expect("claims object"), now)
            .expect_err("fractional nbf is above the leeway boundary");
        assert!(matches!(err, VerificationError::TokenNotValidYet));
    }

    #[test]
    fn rejects_expired_string_numeric_date() {
        let claims = json!({ "exp": "1000000000" });
        let err = validate_time_claims(claims.as_object().expect("claims object"))
            .expect_err("expired string exp");
        assert!(matches!(err, VerificationError::TokenExpired));
    }

    #[test]
    fn rejects_future_string_numeric_date() {
        let claims = json!({ "nbf": "2000000000" });
        let err = validate_time_claims(claims.as_object().expect("claims object"))
            .expect_err("future string nbf");
        assert!(matches!(err, VerificationError::TokenNotValidYet));
    }

    #[test]
    fn rejects_malformed_time_claims() {
        for (claim, value) in [
            ("exp", json!(true)),
            ("exp", json!(null)),
            ("nbf", json!([])),
            ("nbf", json!({})),
        ] {
            let claims = serde_json::Map::from_iter([(claim.to_string(), value)]);
            let err = validate_time_claims(&claims).expect_err("malformed time claim");
            assert!(
                matches!(err, VerificationError::InvalidTimeClaim { .. }),
                "claim={claim} err={err:?}"
            );
        }
    }

    #[test]
    fn rejects_negative_exp_as_expired() {
        // Negative epochs are valid NumericDates and are always in the past.
        let claims = json!({ "exp": -1 });
        let err = validate_time_claims(claims.as_object().expect("claims object"))
            .expect_err("negative exp is expired");
        assert!(matches!(err, VerificationError::TokenExpired));
    }

    #[test]
    fn accepts_far_future_exp_within_i64() {
        let claims = json!({ "exp": i64::MAX });
        assert!(validate_time_claims(claims.as_object().expect("claims object")).is_ok());
    }

    #[test]
    fn verifies_es512_token() {
        let signing_key = SigningKey::generate();
        let public_key = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key");
        let key_file = NamedTempFile::new().expect("create key file");
        fs::write(key_file.path(), public_key).expect("write key file");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES512","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"ES512","exp":{}}}"#, now + 3600));
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );

        let parsed = parser::parse_token(&token).expect("parse token");

        let err = verify_token_signature(
            &parsed,
            Some(key_file.path().to_str().expect("utf-8 path")),
            false,
        );
        assert!(err.is_ok(), "expected ES512 verification to pass: {err:?}");
    }

    #[test]
    fn accepts_es512_token_expired_within_leeway() {
        let signing_key = SigningKey::generate();
        let public_key = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key");
        let key_file = NamedTempFile::new().expect("create key file");
        fs::write(key_file.path(), public_key).expect("write key file");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES512","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"ES512","exp":{}}}"#, now - 30));
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );

        let parsed = parser::parse_token(&token).expect("parse token");

        let err = verify_token_signature(
            &parsed,
            Some(key_file.path().to_str().expect("utf-8 path")),
            false,
        );
        assert!(
            err.is_ok(),
            "expected token within leeway to verify: {err:?}"
        );
    }

    #[test]
    fn rejects_expired_es512_token_unless_ignored() {
        let signing_key = SigningKey::generate();
        let public_key = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key");
        let key_file = NamedTempFile::new().expect("create key file");
        fs::write(key_file.path(), public_key).expect("write key file");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES512","typ":"JWT"}"#);
        let claims = URL_SAFE_NO_PAD.encode(format!(r#"{{"sub":"ES512","exp":{}}}"#, now - 3600));
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = signing_key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        let key_file = key_file.path().to_str().expect("utf-8 path");
        let parsed = parser::parse_token(&token).expect("parse token");

        let err =
            verify_token_signature(&parsed, Some(key_file), false).expect_err("expired token");
        assert!(matches!(err, VerificationError::TokenExpired));

        let err = verify_token_signature(&parsed, Some(key_file), true);
        assert!(
            err.is_ok(),
            "expected expired ES512 token to pass with ignore-expiration: {err:?}"
        );
    }
}
