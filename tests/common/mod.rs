#![allow(dead_code)] // Integration targets use different fixture subsets.

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::json;
use tempfile::NamedTempFile;

pub const RSA_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
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

pub const RSA_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnK9mIR7ghkuWlFESf6H7
F725lmfsrzSRGnwv8Gv4EpFDtskYzgYM11RcJjM0I3eDhjxBnfAs87hplB7/S1WR
yjrArzuu7qICa4VuT5IMTnsXG9gdPbpKTWoYHScYDuUVes3e+jIlpVIQLLMX+sde
l6hkNAVrJ39PuA9+PsSb9qE607FIsHVOIZe8/kNqnWY+0Be7S5zS0XDxnpPB+yCV
dFGApHOVIF3exMc6xQTJxRk0s3kkgUvdQMP+rUsNPG8lsZq2FVm61ZmE/r0H4aQ8
IQd4O4jWd7ucOfKeNVf/yMpoWsQlhw9oDqjBmrKUR+E56RhJtlLLWnKfIrEzFXGO
PQIDAQAB
-----END PUBLIC KEY-----"#;

pub const EC_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5DnJ+IO+xX65e+Xv
a+fs1n4SSW28btlalxltGOUytLuhRANCAAReeGwEr7jUfHkn0oCdupx9MTU31KWr
wcBn792fF0LYtEVaXJHSxsrQPdjSBzKsF3jTbItsh3vxds3cukdZp7nj
-----END PRIVATE KEY-----"#;

pub const EC_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXnhsBK+41Hx5J9KAnbqcfTE1N9Sl
q8HAZ+/dnxdC2LRFWlyR0sbK0D3Y0gcyrBd402yLbId78XbN3LpHWae54w==
-----END PUBLIC KEY-----"#;

pub const ED_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIH2kwYRNLj8oSmGomiH8h5FVRjGjfYsCooSsjVsp/1H4
-----END PRIVATE KEY-----"#;

pub const ED_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAeaMkyhBdLsQXBPbyR1MhzwoJwi+nhiHbru7IAsnyjss=
-----END PUBLIC KEY-----"#;

pub fn unsigned_token(claims: serde_json::Value) -> String {
    token_with_header(json!({ "alg": "none", "typ": "JWT" }), claims)
}

pub fn token_with_header(header: serde_json::Value, claims: serde_json::Value) -> String {
    format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

pub fn hmac_token(secret: &[u8], claims: serde_json::Value) -> String {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("sign HS256 test token")
}

pub fn pem_token(algorithm: Algorithm, private_key: &str, claims: serde_json::Value) -> String {
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

pub fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();

    STANDARD.decode(body).expect("decode PEM body")
}

pub fn key_file(contents: &[u8]) -> NamedTempFile {
    let file = NamedTempFile::new().expect("create key file");
    fs::write(file.path(), contents).expect("write key file");
    file
}

pub fn past_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_secs()
        - 3600
}
