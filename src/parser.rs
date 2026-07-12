use std::sync::LazyLock;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use regex::Regex;
use serde_json::{Map, Value};
use thiserror::Error;

static JWT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        .expect("JWT extraction regex must compile")
});

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedToken {
    pub raw: String,
    pub header: Map<String, Value>,
    pub claims: Map<String, Value>,
    pub signature: String,
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

    #[error("token {segment} is not a JSON object")]
    NotAnObject { segment: &'static str },
}

pub fn parse_token(token: &str) -> Result<ParsedToken, ParseError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(ParseError::InvalidFormat {
            part_count: parts.len(),
            snippet: token_snippet(token),
        });
    }

    let header = decode_json_object(parts[0], token, "header")?;
    let claims = decode_json_object(parts[1], token, "claims")?;

    Ok(ParsedToken {
        raw: token.to_string(),
        header,
        claims,
        signature: parts[2].to_string(),
    })
}

pub fn resolve_token(input: &str, strict: bool) -> Result<ParsedToken, ParseError> {
    let input = input.trim();
    if !strict {
        for candidate in JWT_PATTERN.find_iter(input) {
            if let Ok(parsed) = parse_token(candidate.as_str()) {
                return Ok(parsed);
            }
        }
    }

    parse_token(input)
}

fn decode_json_object(
    segment: &str,
    token: &str,
    segment_name: &'static str,
) -> Result<Map<String, Value>, ParseError> {
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
        _ => Err(ParseError::NotAnObject {
            segment: segment_name,
        }),
    }
}

fn token_snippet(token: &str) -> String {
    if token.len() <= 20 {
        return token.to_string();
    }

    let cut = token
        .char_indices()
        .take(17)
        .last()
        .map_or(17, |(i, c)| i + c.len_utf8());
    format!("{}...", &token[..cut])
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
    fn non_object_header_names_the_segment() {
        let token = format!(
            "{}.{}.",
            encode_segment("[1,2,3]"),
            encode_segment(r#"{"sub":"Abed Nadir"}"#)
        );

        let err = parse_token(&token).expect_err("header is not an object");
        assert_eq!("token header is not a JSON object", err.to_string());
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

        let parsed = resolve_token(&format!("Bearer {token}"), false).expect("extract token");
        assert_eq!(token, parsed.raw);
    }

    #[test]
    fn strict_mode_trims_but_does_not_extract() {
        let token = format!(
            "{}.{}.",
            encode_segment(r#"{"alg":"none","typ":"JWT"}"#),
            encode_segment(r#"{"sub":"Troy Barnes"}"#)
        );

        assert!(resolve_token(&format!("  {token}  "), true).is_ok());
        assert!(resolve_token(&format!("Bearer {token}"), true).is_err());
    }

    #[test]
    fn snippet_does_not_panic_on_multibyte_utf8() {
        let input = "这是没有JWT的中文文本测试一下看看会不会崩溃啊啊啊";
        let err = parse_token(input).expect_err("not a valid token");
        assert!(!err.to_string().is_empty());
    }
}
