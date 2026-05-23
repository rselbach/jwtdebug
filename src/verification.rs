use std::fs;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use p521::ecdsa::signature::Verifier;
use p521::ecdsa::{Signature, VerifyingKey};
use p521::pkcs8::DecodePublicKey;
use serde_json::Value;
use thiserror::Error;

use crate::constants::MAX_FILE_SIZE_BYTES;

const MIN_HMAC_KEY_LEN: usize = 32;

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

    #[error("HMAC key too short: {actual} bytes (minimum {MIN_HMAC_KEY_LEN})")]
    HmacKeyTooShort { actual: usize },

    #[error("unexpected signing method: {0}")]
    UnexpectedAlgorithm(String),

    #[error("invalid token format: expected 3 parts separated by '.', got {0}")]
    InvalidTokenParts(usize),

    #[error("failed to decode token header: {0}")]
    DecodeHeader(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("failed to decode token signature: {0}")]
    DecodeSignature(#[source] base64::DecodeError),

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

    #[error(transparent)]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub fn verify_token_signature(
    token: &str,
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
    let algorithm_name = algorithm_name(token)?;
    if algorithm_name == "ES512" {
        return verify_es512(token, &key_data, ignore_expiration);
    }

    let algorithm = Algorithm::from_str(&algorithm_name)
        .map_err(|_| VerificationError::UnexpectedAlgorithm(algorithm_name.clone()))?;
    let key = decoding_key(algorithm, &key_data)?;

    let mut validation = Validation::new(algorithm);
    validation.algorithms = vec![algorithm];
    validation.required_spec_claims.clear();
    validation.validate_exp = !ignore_expiration;
    validation.validate_nbf = !ignore_expiration;

    decode::<Value>(token, &key, &validation)?;
    Ok(())
}

fn decoding_key(algorithm: Algorithm, key_data: &[u8]) -> Result<DecodingKey, VerificationError> {
    match algorithm {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if key_data.len() < MIN_HMAC_KEY_LEN {
                return Err(VerificationError::HmacKeyTooShort {
                    actual: key_data.len(),
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

fn algorithm_name(token: &str) -> Result<String, VerificationError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(VerificationError::InvalidTokenParts(parts.len()));
    }

    let header_data = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|err| VerificationError::DecodeHeader(Box::new(err)))?;
    let header = serde_json::from_slice::<Value>(&header_data)
        .map_err(|err| VerificationError::DecodeHeader(Box::new(err)))?;

    header
        .get("alg")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| VerificationError::UnexpectedAlgorithm("<missing>".to_string()))
}

fn verify_es512(
    token: &str,
    key_data: &[u8],
    ignore_expiration: bool,
) -> Result<(), VerificationError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(VerificationError::InvalidTokenParts(parts.len()));
    }

    let signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(VerificationError::DecodeSignature)?;
    let signature = Signature::from_slice(&signature).map_err(VerificationError::Es512Signature)?;
    let key_pem = std::str::from_utf8(key_data)
        .map_err(|err| VerificationError::DecodeHeader(Box::new(err)))?;
    let verifying_key =
        VerifyingKey::from_public_key_pem(key_pem).map_err(VerificationError::Es512Key)?;

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| VerificationError::SignatureInvalid)?;

    if !ignore_expiration {
        validate_time_claims(parts[1])?;
    }

    Ok(())
}

fn validate_time_claims(payload: &str) -> Result<(), VerificationError> {
    let data = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|err| VerificationError::DecodeHeader(Box::new(err)))?;
    let claims = serde_json::from_slice::<Value>(&data)
        .map_err(|err| VerificationError::DecodeHeader(Box::new(err)))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64);

    if let Some(exp) = claims.get("exp").and_then(value_as_i64) {
        if now > exp {
            return Err(VerificationError::TokenExpired);
        }
    }

    if let Some(nbf) = claims.get("nbf").and_then(value_as_i64) {
        if now < nbf {
            return Err(VerificationError::TokenNotValidYet);
        }
    }

    Ok(())
}

fn value_as_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|n| n.try_into().ok())),
        _ => None,
    }
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
    use tempfile::NamedTempFile;

    use super::*;

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

        let err = verify_token_signature(
            &token,
            Some(key_file.path().to_str().expect("utf-8 path")),
            false,
        );
        assert!(err.is_ok(), "expected ES512 verification to pass: {err:?}");
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

        let err = verify_token_signature(&token, Some(key_file), false).expect_err("expired token");
        assert!(matches!(err, VerificationError::TokenExpired));

        let err = verify_token_signature(&token, Some(key_file), true);
        assert!(
            err.is_ok(),
            "expected expired ES512 token to pass with ignore-expiration: {err:?}"
        );
    }
}
