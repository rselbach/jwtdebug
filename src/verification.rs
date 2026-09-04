use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::pkcs8::DecodePublicKey as _;
use hmac::Hmac;
use p256::ecdsa::VerifyingKey as P256Key;
use p384::ecdsa::VerifyingKey as P384Key;
use p521::ecdsa::VerifyingKey as P521Key;
use p521::ecdsa::signature::Verifier as _;
use p521::pkcs8::DecodePublicKey as _;
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey as _;
use rsa::traits::PublicKeyParts as _;
use serde_json::{Map, Value};
use sha2::{Sha256, Sha384, Sha512};
use signature::Verifier as _;
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::der::{Decode as _, Encode as _};

use crate::constants::MAX_KEY_FILE_SIZE;
use crate::output::escape_for_terminal;
use crate::parser::{ParsedToken, decode_base64_url};
use crate::time_claims::{TimeClaim, UnixTime, classify};

const TIME_LEEWAY_SECONDS: i128 = 60;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("key file not provided (--key-file / -k required)")]
    MissingKeyFile,

    #[error("expected signing algorithm not provided (--algorithm required)")]
    MissingAlgorithm,

    #[error("failed to open key file: {0}")]
    OpenKeyFile(#[source] std::io::Error),

    #[error("key file must be a regular file")]
    KeyFileNotRegular,

    #[error("key file too large (max {MAX_KEY_FILE_SIZE} bytes)")]
    KeyFileTooLarge,

    #[error("failed to read key file: {0}")]
    ReadKeyFile(#[source] std::io::Error),

    #[error("HMAC key file contains an asymmetric key")]
    HmacKeyIsAsymmetric,

    #[error("unexpected signing method: {0}")]
    UnexpectedAlgorithm(String),

    #[error("failed to parse {algorithm} public key: {message}")]
    PublicKey {
        algorithm: &'static str,
        message: String,
    },

    #[error("token signing algorithm {actual} does not match expected algorithm {expected}")]
    AlgorithmMismatch {
        expected: &'static str,
        actual: String,
    },

    #[error("unexpected signing method: <missing>")]
    MissingTokenAlgorithm,

    #[error("invalid b64 header: expected a boolean")]
    InvalidB64Header,

    #[error("unsupported b64 header: false is not valid for JWTs")]
    UnsupportedB64Header,

    #[error("unsupported critical header parameters")]
    UnsupportedCriticalHeaders,

    #[error("failed to decode token signature: {0}")]
    DecodeSignature(String),

    #[error("failed to parse ES512 signature: invalid signature length {0}")]
    Es512Signature(usize),

    #[error("signature is invalid")]
    InvalidSignature,

    #[error(
        "signature is invalid (key file ends with a newline; if that is not part of the secret, write it with `printf %s` or `echo -n`)"
    )]
    InvalidSignatureTrailingNewline,

    #[error("token is expired")]
    Expired,

    #[error("token is not valid yet")]
    NotValidYet,

    #[error("invalid {claim} claim: {value}")]
    InvalidTimeClaim { claim: &'static str, value: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeakHmacKeyWarning {
    pub actual: usize,
    pub minimum: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    EdDsa,
}

impl Algorithm {
    fn parse(name: &str) -> Result<Self, VerificationError> {
        match name {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "ES512" => Ok(Self::ES512),
            "EdDSA" => Ok(Self::EdDsa),
            _ => Err(VerificationError::UnexpectedAlgorithm(name.to_owned())),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::EdDsa => "EdDSA",
        }
    }

    const fn minimum_hmac_key_size(self) -> Option<usize> {
        match self {
            Self::HS256 => Some(32),
            Self::HS384 => Some(48),
            Self::HS512 => Some(64),
            _ => None,
        }
    }
}

enum VerificationKey {
    Hmac(Vec<u8>),
    Rsa(RsaPublicKey),
    P256(P256Key),
    P384(P384Key),
    P521(P521Key),
    Ed25519(ed25519_dalek::VerifyingKey),
}

pub struct Verifier {
    algorithm: Algorithm,
    key: VerificationKey,
    ignore_expiration: bool,
    hmac_key_has_trailing_newline: bool,
    weak_hmac_key_warning: Option<WeakHmacKeyWarning>,
}

impl Verifier {
    pub fn new(
        key_file: Option<&str>,
        expected_algorithm: Option<&str>,
        ignore_expiration: bool,
    ) -> Result<Self, VerificationError> {
        let key_file = key_file
            .filter(|path| !path.is_empty())
            .ok_or(VerificationError::MissingKeyFile)?;
        let algorithm = Algorithm::parse(
            expected_algorithm
                .filter(|name| !name.is_empty())
                .ok_or(VerificationError::MissingAlgorithm)?,
        )?;
        let key_data = read_key_file(Path::new(key_file))?;
        let (key, weak_hmac_key_warning) = prepare_key(algorithm, &key_data)?;

        Ok(Self {
            algorithm,
            key,
            ignore_expiration,
            hmac_key_has_trailing_newline: key_data.ends_with(b"\n"),
            weak_hmac_key_warning,
        })
    }

    pub fn weak_hmac_key_warning(&self) -> Option<WeakHmacKeyWarning> {
        self.weak_hmac_key_warning
    }

    pub fn verify(&self, token: &ParsedToken, now: UnixTime) -> Result<(), VerificationError> {
        let actual = token
            .header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(VerificationError::MissingTokenAlgorithm)?;
        if actual != self.algorithm.name() {
            return Err(VerificationError::AlgorithmMismatch {
                expected: self.algorithm.name(),
                actual: escape_for_terminal(actual),
            });
        }
        validate_protected_header(&token.header)?;

        let (signing_input, _) = token
            .raw
            .rsplit_once('.')
            .expect("parsed JWTs always have three segments");
        let signature =
            decode_base64_url(&token.signature).map_err(VerificationError::DecodeSignature)?;
        if let Err(error) = self.verify_signature(signing_input.as_bytes(), &signature) {
            if matches!(self.key, VerificationKey::Hmac(_))
                && self.hmac_key_has_trailing_newline
                && matches!(error, VerificationError::InvalidSignature)
            {
                return Err(VerificationError::InvalidSignatureTrailingNewline);
            }
            return Err(error);
        }

        validate_time_claims(&token.claims, now, self.ignore_expiration)
    }

    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), VerificationError> {
        match (self.algorithm, &self.key) {
            (Algorithm::HS256, VerificationKey::Hmac(key)) => {
                verify_hmac::<Hmac<Sha256>>(key, message, signature)
            }
            (Algorithm::HS384, VerificationKey::Hmac(key)) => {
                verify_hmac::<Hmac<Sha384>>(key, message, signature)
            }
            (Algorithm::HS512, VerificationKey::Hmac(key)) => {
                verify_hmac::<Hmac<Sha512>>(key, message, signature)
            }
            (Algorithm::RS256, VerificationKey::Rsa(key)) => {
                verify_rsa_pkcs1::<Sha256>(key, message, signature)
            }
            (Algorithm::RS384, VerificationKey::Rsa(key)) => {
                verify_rsa_pkcs1::<Sha384>(key, message, signature)
            }
            (Algorithm::RS512, VerificationKey::Rsa(key)) => {
                verify_rsa_pkcs1::<Sha512>(key, message, signature)
            }
            (Algorithm::PS256, VerificationKey::Rsa(key)) => {
                verify_rsa_pss::<Sha256>(key, message, signature, 32)
            }
            (Algorithm::PS384, VerificationKey::Rsa(key)) => {
                verify_rsa_pss::<Sha384>(key, message, signature, 48)
            }
            (Algorithm::PS512, VerificationKey::Rsa(key)) => {
                verify_rsa_pss::<Sha512>(key, message, signature, 64)
            }
            (Algorithm::ES256, VerificationKey::P256(key)) => {
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                key.verify(message, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            (Algorithm::ES384, VerificationKey::P384(key)) => {
                let signature = p384::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                key.verify(message, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            (Algorithm::ES512, VerificationKey::P521(key)) => {
                let signature = p521::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| VerificationError::Es512Signature(signature.len()))?;
                key.verify(message, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            (Algorithm::EdDsa, VerificationKey::Ed25519(key)) => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| VerificationError::InvalidSignature)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| VerificationError::InvalidSignature)
            }
            _ => unreachable!("algorithm and prepared key family always agree"),
        }
    }
}

fn validate_protected_header(header: &Map<String, Value>) -> Result<(), VerificationError> {
    if let Some(value) = header.get("b64") {
        match value.as_bool() {
            Some(true) => {}
            Some(false) => return Err(VerificationError::UnsupportedB64Header),
            None => return Err(VerificationError::InvalidB64Header),
        }
    }
    if header.contains_key("crit") {
        return Err(VerificationError::UnsupportedCriticalHeaders);
    }
    Ok(())
}

fn verify_hmac<M>(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), VerificationError>
where
    M: hmac::digest::KeyInit + hmac::digest::Mac,
{
    let mut mac =
        <M as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(message);
    mac.verify_slice(signature)
        .map_err(|_| VerificationError::InvalidSignature)
}

fn verify_rsa_pkcs1<D>(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerificationError>
where
    D: sha2::Digest + sha2::digest::FixedOutputReset + Default + Clone + 'static,
    D: rsa::pkcs8::AssociatedOid,
{
    let signature = rsa::pkcs1v15::Signature::try_from(signature)
        .map_err(|_| VerificationError::InvalidSignature)?;
    rsa::pkcs1v15::VerifyingKey::<D>::new(key.clone())
        .verify(message, &signature)
        .map_err(|_| VerificationError::InvalidSignature)
}

fn verify_rsa_pss<D>(
    key: &RsaPublicKey,
    message: &[u8],
    signature: &[u8],
    salt_length: usize,
) -> Result<(), VerificationError>
where
    D: sha2::Digest + sha2::digest::FixedOutputReset + Default + Clone + 'static,
{
    let signature = rsa::pss::Signature::try_from(signature)
        .map_err(|_| VerificationError::InvalidSignature)?;
    rsa::pss::VerifyingKey::<D>::new_with_salt_len(key.clone(), salt_length)
        .verify(message, &signature)
        .map_err(|_| VerificationError::InvalidSignature)
}

fn prepare_key(
    algorithm: Algorithm,
    data: &[u8],
) -> Result<(VerificationKey, Option<WeakHmacKeyWarning>), VerificationError> {
    if let Some(minimum) = algorithm.minimum_hmac_key_size() {
        if is_asymmetric_key(data) {
            return Err(VerificationError::HmacKeyIsAsymmetric);
        }
        let warning = (data.len() < minimum).then_some(WeakHmacKeyWarning {
            actual: data.len(),
            minimum,
        });
        return Ok((VerificationKey::Hmac(data.to_vec()), warning));
    }

    let der = decode_public_key_material(data).map_err(|message| VerificationError::PublicKey {
        algorithm: algorithm.name(),
        message: message.to_owned(),
    })?;
    let der = certificate_public_key(&der).unwrap_or(der);
    let key = match algorithm {
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            let key = RsaPublicKey::from_public_key_der(&der)
                .or_else(|_| RsaPublicKey::from_pkcs1_der(&der))
                .map_err(|_| VerificationError::PublicKey {
                    algorithm: algorithm.name(),
                    message: "expected RSA key".to_owned(),
                })?;
            if key.n().bits() < 2048 {
                return Err(VerificationError::PublicKey {
                    algorithm: algorithm.name(),
                    message: "RSA modulus must be at least 2048 bits".to_owned(),
                });
            }
            VerificationKey::Rsa(key)
        }
        Algorithm::ES256 => {
            VerificationKey::P256(P256Key::from_public_key_der(&der).map_err(|_| {
                VerificationError::PublicKey {
                    algorithm: algorithm.name(),
                    message: "expected P-256 curve".to_owned(),
                }
            })?)
        }
        Algorithm::ES384 => {
            VerificationKey::P384(P384Key::from_public_key_der(&der).map_err(|_| {
                VerificationError::PublicKey {
                    algorithm: algorithm.name(),
                    message: "expected P-384 curve".to_owned(),
                }
            })?)
        }
        Algorithm::ES512 => {
            VerificationKey::P521(P521Key::from_public_key_der(&der).map_err(|_| {
                VerificationError::PublicKey {
                    algorithm: algorithm.name(),
                    message: "expected P-521 curve".to_owned(),
                }
            })?)
        }
        Algorithm::EdDsa => VerificationKey::Ed25519(
            ed25519_dalek::VerifyingKey::from_public_key_der(&der).map_err(|_| {
                VerificationError::PublicKey {
                    algorithm: algorithm.name(),
                    message: "expected Ed25519 key".to_owned(),
                }
            })?,
        ),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => unreachable!(),
    };
    Ok((key, None))
}

fn read_key_file(path: &Path) -> Result<Vec<u8>, VerificationError> {
    if !std::fs::metadata(path)
        .map_err(VerificationError::OpenKeyFile)?
        .is_file()
    {
        return Err(VerificationError::KeyFileNotRegular);
    }

    let file = File::open(path).map_err(VerificationError::OpenKeyFile)?;
    if !file
        .metadata()
        .map_err(VerificationError::OpenKeyFile)?
        .is_file()
    {
        return Err(VerificationError::KeyFileNotRegular);
    }

    let mut data = Vec::new();
    file.take((MAX_KEY_FILE_SIZE + 1) as u64)
        .read_to_end(&mut data)
        .map_err(VerificationError::ReadKeyFile)?;
    if data.len() > MAX_KEY_FILE_SIZE {
        return Err(VerificationError::KeyFileTooLarge);
    }
    Ok(data)
}

fn decode_public_key_material(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let trimmed = trim_ascii_whitespace(data);
    if !trimmed.starts_with(b"-----BEGIN ") {
        return Err("invalid PEM data");
    }
    let text = std::str::from_utf8(trimmed).map_err(|_| "invalid PEM data")?;
    let mut lines = text.lines();
    let header = lines.next().ok_or("invalid PEM data")?;
    let label = header
        .strip_prefix("-----BEGIN ")
        .and_then(|header| header.strip_suffix("-----"))
        .filter(|label| !label.is_empty())
        .ok_or("invalid PEM data")?;
    let footer = format!("-----END {label}-----");
    let mut body = String::new();
    let mut found_footer = false;
    for line in &mut lines {
        if line == footer {
            found_footer = true;
            break;
        }
        body.push_str(line.trim());
    }
    if !found_footer {
        return Err("invalid PEM data");
    }
    if lines.any(|line| !line.trim().is_empty()) {
        return Err("public key PEM contains multiple blocks or trailing data");
    }
    STANDARD
        .decode(body)
        .map_err(|_| "unsupported public key format")
}

fn certificate_public_key(der: &[u8]) -> Option<Vec<u8>> {
    Certificate::from_der(der)
        .ok()?
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()
}

fn is_asymmetric_key(data: &[u8]) -> bool {
    if let Ok(text) = std::str::from_utf8(data)
        && let Some(begin) = text.find("-----BEGIN ")
        && let Some(label_end) = text[begin + 11..].find("-----")
    {
        let label = &text[begin + 11..begin + 11 + label_end];
        if label.contains("KEY") || label == "CERTIFICATE" {
            return true;
        }
    }

    spki::SubjectPublicKeyInfoRef::try_from(data).is_ok()
        || pkcs8::PrivateKeyInfo::try_from(data).is_ok()
        || sec1::EcPrivateKey::try_from(data).is_ok()
        || RsaPublicKey::from_pkcs1_der(data).is_ok()
        || Certificate::from_der(data).is_ok()
}

fn trim_ascii_whitespace(mut data: &[u8]) -> &[u8] {
    while data.first().is_some_and(u8::is_ascii_whitespace) {
        data = &data[1..];
    }
    while data.last().is_some_and(u8::is_ascii_whitespace) {
        data = &data[..data.len() - 1];
    }
    data
}

fn validate_time_claims(
    claims: &Map<String, Value>,
    now: UnixTime,
    ignore_expiration: bool,
) -> Result<(), VerificationError> {
    if !ignore_expiration {
        match classify(claims, "exp") {
            TimeClaim::Invalid(value) => {
                return Err(VerificationError::InvalidTimeClaim {
                    claim: "exp",
                    value: value.to_string(),
                });
            }
            TimeClaim::Valid(expiration)
                if expiration.is_before(now.add_seconds(-TIME_LEEWAY_SECONDS)) =>
            {
                return Err(VerificationError::Expired);
            }
            TimeClaim::Absent | TimeClaim::Valid(_) => {}
        }
    }

    match classify(claims, "nbf") {
        TimeClaim::Invalid(value) => Err(VerificationError::InvalidTimeClaim {
            claim: "nbf",
            value: value.to_string(),
        }),
        TimeClaim::Valid(not_before)
            if not_before.is_after(now.add_seconds(TIME_LEEWAY_SECONDS)) =>
        {
            Err(VerificationError::NotValidYet)
        }
        TimeClaim::Absent | TimeClaim::Valid(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use hmac::Mac as _;
    use p256::pkcs8::EncodePublicKey as _;
    use p521::ecdsa::signature::Signer as _;
    use p521::elliptic_curve::Generate as _;
    use p521::pkcs8::EncodePublicKey as _;
    use rand::rngs::OsRng;
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};

    use super::*;
    use crate::parser::parse_token;

    fn hmac_token(secret: &[u8], header: Value, claims: Value) -> ParsedToken {
        let header = URL_SAFE_NO_PAD.encode(header.to_string());
        let claims = URL_SAFE_NO_PAD.encode(claims.to_string());
        let signing_input = format!("{header}.{claims}");
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC key");
        mac.update(signing_input.as_bytes());
        parse_token(&format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        ))
        .expect("parse signed token")
    }

    fn verifier(algorithm: Algorithm, key: VerificationKey) -> Verifier {
        Verifier {
            algorithm,
            key,
            ignore_expiration: false,
            hmac_key_has_trailing_newline: false,
            weak_hmac_key_warning: None,
        }
    }

    fn pem(der: &[u8]) -> Vec<u8> {
        let encoded = STANDARD.encode(der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(line).expect("base64 is UTF-8"));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem.into_bytes()
    }

    #[test]
    fn verifies_hmac_and_time_claims() {
        let secret = b"test-secret-key-at-least-32-bytes-long!";
        let token = hmac_token(
            secret,
            json!({ "alg": "HS256" }),
            json!({ "sub": "Annie Edison", "exp": 1_700_000_100 }),
        );
        let (key, warning) = prepare_key(Algorithm::HS256, secret).expect("prepare key");
        let verifier = Verifier {
            algorithm: Algorithm::HS256,
            key,
            ignore_expiration: false,
            hmac_key_has_trailing_newline: false,
            weak_hmac_key_warning: warning,
        };

        assert!(
            verifier
                .verify(&token, UnixTime::new(1_700_000_000, 0))
                .is_ok()
        );
        assert!(matches!(
            verifier.verify(&token, UnixTime::new(1_700_001_000, 0)),
            Err(VerificationError::Expired)
        ));
    }

    #[test]
    fn rejects_unsupported_protected_headers_before_claims_are_trusted() {
        for (header, expected) in [
            (
                json!({ "alg": "HS256", "b64": false }),
                VerificationError::UnsupportedB64Header,
            ),
            (
                json!({ "alg": "HS256", "b64": "false" }),
                VerificationError::InvalidB64Header,
            ),
            (
                json!({ "alg": "HS256", "crit": ["example"] }),
                VerificationError::UnsupportedCriticalHeaders,
            ),
        ] {
            let error = validate_protected_header(header.as_object().expect("object"))
                .expect_err("unsupported header");
            assert_eq!(error.to_string(), expected.to_string());
        }
    }

    #[test]
    fn rejects_out_of_range_and_subsecond_time_claims() {
        let now = UnixTime::new(1_700_000_000, 500_000_000);
        for claims in [
            json!({ "exp": 1_699_999_940 }),
            json!({ "exp": 1_699_999_939.6 }),
        ] {
            assert!(matches!(
                validate_time_claims(claims.as_object().expect("object"), now, false),
                Err(VerificationError::Expired)
            ));
        }
        assert!(matches!(
            validate_time_claims(
                json!({ "nbf": 1_700_000_060.6 })
                    .as_object()
                    .expect("object"),
                now,
                false,
            ),
            Err(VerificationError::NotValidYet)
        ));
    }

    #[test]
    fn pem_parser_rejects_leading_trailing_and_multiple_data() {
        let valid = b"-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n";
        assert_eq!(decode_public_key_material(valid).expect("PEM"), [1, 2, 3]);
        assert_eq!(
            decode_public_key_material(&[b"leading".as_slice(), valid].concat()),
            Err("invalid PEM data")
        );
        assert_eq!(
            decode_public_key_material(&[valid.as_slice(), b"trailing"].concat()),
            Err("public key PEM contains multiple blocks or trailing data")
        );
        assert_eq!(
            decode_public_key_material(&[valid.as_slice(), valid].concat()),
            Err("public key PEM contains multiple blocks or trailing data")
        );
    }

    #[test]
    fn all_supported_algorithms_verify() {
        let message = b"eyJhbGciOiJ0ZXN0In0.eyJzdWIiOiJ0ZXN0In0";

        for (algorithm, key) in [
            (
                Algorithm::HS256,
                b"a secure HS256 key with 32 bytes!".as_slice(),
            ),
            (
                Algorithm::HS384,
                b"a secure HS384 key with at least forty-eight bytes!!".as_slice(),
            ),
            (
                Algorithm::HS512,
                b"a secure HS512 key with at least sixty-four bytes for this test!!!".as_slice(),
            ),
        ] {
            let signature = match algorithm {
                Algorithm::HS256 => {
                    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key");
                    mac.update(message);
                    mac.finalize().into_bytes().to_vec()
                }
                Algorithm::HS384 => {
                    let mut mac = Hmac::<Sha384>::new_from_slice(key).expect("HMAC key");
                    mac.update(message);
                    mac.finalize().into_bytes().to_vec()
                }
                Algorithm::HS512 => {
                    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC key");
                    mac.update(message);
                    mac.finalize().into_bytes().to_vec()
                }
                _ => unreachable!(),
            };
            verifier(algorithm, VerificationKey::Hmac(key.to_vec()))
                .verify_signature(message, &signature)
                .unwrap_or_else(|error| panic!("{}: {error}", algorithm.name()));
        }

        let mut rng = OsRng;
        let rsa_private = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let rsa_public = rsa_private.to_public_key();
        let rs256: rsa::pkcs1v15::Signature =
            rsa::pkcs1v15::SigningKey::<Sha256>::new(rsa_private.clone()).sign(message);
        let rs384: rsa::pkcs1v15::Signature =
            rsa::pkcs1v15::SigningKey::<Sha384>::new(rsa_private.clone()).sign(message);
        let rs512: rsa::pkcs1v15::Signature =
            rsa::pkcs1v15::SigningKey::<Sha512>::new(rsa_private.clone()).sign(message);
        for (algorithm, signature) in [
            (Algorithm::RS256, rs256.to_vec()),
            (Algorithm::RS384, rs384.to_vec()),
            (Algorithm::RS512, rs512.to_vec()),
        ] {
            verifier(algorithm, VerificationKey::Rsa(rsa_public.clone()))
                .verify_signature(message, &signature)
                .unwrap_or_else(|error| panic!("{}: {error}", algorithm.name()));
        }

        let ps256: rsa::pss::Signature =
            rsa::pss::BlindedSigningKey::<Sha256>::new_with_salt_len(rsa_private.clone(), 32)
                .sign_with_rng(&mut rng, message);
        let ps384: rsa::pss::Signature =
            rsa::pss::BlindedSigningKey::<Sha384>::new_with_salt_len(rsa_private.clone(), 48)
                .sign_with_rng(&mut rng, message);
        let ps512: rsa::pss::Signature =
            rsa::pss::BlindedSigningKey::<Sha512>::new_with_salt_len(rsa_private.clone(), 64)
                .sign_with_rng(&mut rng, message);
        for (algorithm, signature) in [
            (Algorithm::PS256, ps256.to_vec()),
            (Algorithm::PS384, ps384.to_vec()),
            (Algorithm::PS512, ps512.to_vec()),
        ] {
            verifier(algorithm, VerificationKey::Rsa(rsa_public.clone()))
                .verify_signature(message, &signature)
                .unwrap_or_else(|error| panic!("{}: {error}", algorithm.name()));
        }

        let p256_signing = p256::ecdsa::SigningKey::random(&mut rng);
        let p256_signature: p256::ecdsa::Signature = p256_signing.sign(message);
        verifier(
            Algorithm::ES256,
            VerificationKey::P256(*p256_signing.verifying_key()),
        )
        .verify_signature(message, &p256_signature.to_bytes())
        .expect("ES256");

        let p384_signing = p384::ecdsa::SigningKey::random(&mut rng);
        let p384_signature: p384::ecdsa::Signature = p384_signing.sign(message);
        verifier(
            Algorithm::ES384,
            VerificationKey::P384(*p384_signing.verifying_key()),
        )
        .verify_signature(message, &p384_signature.to_bytes())
        .expect("ES384");

        let p521_signing = p521::ecdsa::SigningKey::generate();
        let p521_signature: p521::ecdsa::Signature = p521_signing.sign(message);
        verifier(
            Algorithm::ES512,
            VerificationKey::P521(*p521_signing.verifying_key()),
        )
        .verify_signature(message, &p521_signature.to_bytes())
        .expect("ES512");

        let ed25519_signing = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let ed25519_signature = ed25519_signing.sign(message);
        verifier(
            Algorithm::EdDsa,
            VerificationKey::Ed25519(ed25519_signing.verifying_key()),
        )
        .verify_signature(message, &ed25519_signature.to_bytes())
        .expect("EdDSA");
    }

    #[test]
    fn public_key_parser_accepts_each_supported_key_family() {
        let mut rng = OsRng;
        let rsa = RsaPrivateKey::new(&mut rng, 2048)
            .expect("generate RSA key")
            .to_public_key()
            .to_public_key_der()
            .expect("encode RSA key");
        assert!(matches!(
            prepare_key(Algorithm::RS256, &pem(rsa.as_bytes())),
            Ok((VerificationKey::Rsa(_), None))
        ));

        let p256 = p256::ecdsa::SigningKey::random(&mut rng);
        let p256 = p256
            .verifying_key()
            .to_public_key_der()
            .expect("encode P-256 key");
        assert!(matches!(
            prepare_key(Algorithm::ES256, &pem(p256.as_bytes())),
            Ok((VerificationKey::P256(_), None))
        ));

        let p384 = p384::ecdsa::SigningKey::random(&mut rng);
        let p384 = p384
            .verifying_key()
            .to_public_key_der()
            .expect("encode P-384 key");
        assert!(matches!(
            prepare_key(Algorithm::ES384, &pem(p384.as_bytes())),
            Ok((VerificationKey::P384(_), None))
        ));

        let p521 = p521::ecdsa::SigningKey::generate();
        let p521 = p521
            .verifying_key()
            .to_public_key_der()
            .expect("encode P-521 key");
        assert!(matches!(
            prepare_key(Algorithm::ES512, &pem(p521.as_bytes())),
            Ok((VerificationKey::P521(_), None))
        ));

        let ed25519 = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let ed25519 = ed25519
            .verifying_key()
            .to_public_key_der()
            .expect("encode Ed25519 key");
        assert!(matches!(
            prepare_key(Algorithm::EdDsa, &pem(ed25519.as_bytes())),
            Ok((VerificationKey::Ed25519(_), None))
        ));
    }
}
