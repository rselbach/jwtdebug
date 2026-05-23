use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;
use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedToken {
    pub header: Map<String, Value>,
    pub claims: Map<String, Value>,
    pub parts: Vec<String>,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid token format: expected 3 parts separated by '.', got {part_count} (token: {snippet})")]
    InvalidFormat { part_count: usize, snippet: String },

    #[error("failed to parse token ({snippet}): {source}")]
    Decode {
        snippet: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("could not extract claims from token")]
    ClaimsNotObject,
}

pub fn parse_token(token: &str) -> Result<ParsedToken, ParseError> {
    let parts = token.split('.').map(str::to_string).collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(ParseError::InvalidFormat {
            part_count: parts.len(),
            snippet: token_snippet(token),
        });
    }

    let header = decode_json_object(&parts[0], token)?;
    let claims = decode_json_object(&parts[1], token)?;

    Ok(ParsedToken {
        header,
        claims,
        parts,
    })
}

pub fn normalize_token_string(s: &str, strict: bool) -> String {
    let s = s.trim();
    if s.is_empty() || strict {
        return s.to_string();
    }

    let pattern = Regex::new(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        .expect("JWT extraction regex must compile");
    for candidate in pattern.find_iter(s) {
        let candidate = candidate.as_str();
        if parse_token(candidate).is_ok() {
            return candidate.to_string();
        }
    }

    s.to_string()
}

fn decode_json_object(segment: &str, token: &str) -> Result<Map<String, Value>, ParseError> {
    let data = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|source| ParseError::Decode {
            snippet: token_snippet(token),
            source: Box::new(source),
        })?;

    match serde_json::from_slice::<Value>(&data).map_err(|source| ParseError::Decode {
        snippet: token_snippet(token),
        source: Box::new(source),
    })? {
        Value::Object(obj) => Ok(obj),
        _ => Err(ParseError::ClaimsNotObject),
    }
}

fn token_snippet(token: &str) -> String {
    if token.len() <= 20 {
        return token.to_string();
    }

    format!("{}...", &token[..17])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_segment(s: &str) -> String {
        URL_SAFE_NO_PAD.encode(s)
    }

    #[test]
    fn parses_valid_token() {
        let token = format!(
            "{}.{}.c2lnbmF0dXJl",
            encode_segment(r#"{"alg":"HS256","typ":"JWT"}"#),
            encode_segment(r#"{"sub":"1234567890"}"#)
        );

        let parsed = parse_token(&token).expect("parse token");
        assert_eq!(
            Some(&Value::String("1234567890".to_string())),
            parsed.claims.get("sub")
        );
    }

    #[test]
    fn rejects_invalid_part_count() {
        let err = parse_token("invalid.token").expect_err("invalid token");
        assert!(err.to_string().contains("invalid token format"));
    }

    #[test]
    fn preserves_large_numbers() {
        let token = format!(
            "{}.{}.",
            encode_segment(r#"{"alg":"none","typ":"JWT"}"#),
            encode_segment(r#"{"id":9007199254740993}"#)
        );

        let parsed = parse_token(&token).expect("parse token");
        assert_eq!("9007199254740993", parsed.claims["id"].to_string());
    }

    #[test]
    fn smart_extraction_returns_first_parseable_jwt() {
        let token = format!(
            "{}.{}.",
            encode_segment(r#"{"alg":"none","typ":"JWT"}"#),
            encode_segment(r#"{"sub":"Troy Barnes"}"#)
        );

        assert_eq!(
            token,
            normalize_token_string(&format!("Bearer {token}"), false)
        );
    }

    #[test]
    fn strict_mode_only_trims() {
        assert_eq!(
            "Bearer not.a.jwt",
            normalize_token_string("  Bearer not.a.jwt  ", true)
        );
    }
}
