use std::sync::LazyLock;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use regex::Regex;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::output::escape_for_terminal;

static JWT_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        .expect("the JWT extraction regex is valid")
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
    #[error(
        "invalid token format: expected 3 parts separated by '.', got {part_count} (token: {snippet})"
    )]
    InvalidFormat { part_count: usize, snippet: String },

    #[error("failed to parse token ({snippet}): {message}")]
    Decode { snippet: String, message: String },

    #[error("failed to decode token signature ({snippet}): {message}")]
    InvalidSignature { snippet: String, message: String },

    #[error("token {segment} is not a JSON object")]
    NotAnObject { segment: &'static str },
}

pub fn parse_token(token: &str) -> Result<ParsedToken, ParseError> {
    let mut parts = token.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(ParseError::InvalidFormat {
            part_count: token.split('.').count(),
            snippet: token_snippet(token),
        });
    };

    let header = decode_json_object(header, token, "header")?;
    let claims = decode_json_object(claims, token, "claims")?;
    decode_base64_url(signature).map_err(|message| ParseError::InvalidSignature {
        snippet: token_snippet(token),
        message,
    })?;

    Ok(ParsedToken {
        raw: token.to_owned(),
        header,
        claims,
        signature: signature.to_owned(),
    })
}

pub fn resolve_token(input: &str, strict: bool) -> Result<ParsedToken, ParseError> {
    let input = input.trim();
    let exact_error = match parse_token(input) {
        Ok(parsed) => return Ok(parsed),
        Err(error) => error,
    };
    if strict {
        return Err(exact_error);
    }

    JWT_PATTERN
        .find_iter(input)
        .filter(|candidate| has_extraction_boundaries(input, candidate.start(), candidate.end()))
        .find_map(|candidate| parse_token(candidate.as_str()).ok())
        .ok_or(exact_error)
}

pub fn decode_base64_url(segment: &str) -> Result<Vec<u8>, String> {
    if let Some((index, _)) = segment
        .bytes()
        .enumerate()
        .find(|(_, byte)| !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'-'))
    {
        return Err(format!("invalid base64url character at byte {index}"));
    }
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|error| error.to_string())
}

fn decode_json_object(
    segment: &str,
    token: &str,
    segment_name: &'static str,
) -> Result<Map<String, Value>, ParseError> {
    let data = decode_base64_url(segment).map_err(|message| ParseError::Decode {
        snippet: token_snippet(token),
        message,
    })?;
    let text = std::str::from_utf8(&data).map_err(|_| ParseError::Decode {
        snippet: token_snippet(token),
        message: "JSON segment is not valid UTF-8".to_owned(),
    })?;
    match serde_json::from_str(text).map_err(|error| ParseError::Decode {
        snippet: token_snippet(token),
        message: error.to_string(),
    })? {
        Value::Object(object) => Ok(object),
        _ => Err(ParseError::NotAnObject {
            segment: segment_name,
        }),
    }
}

fn has_extraction_boundaries(input: &str, start: usize, end: usize) -> bool {
    input[..start]
        .chars()
        .next_back()
        .is_none_or(is_extraction_boundary)
        && input[end..]
            .chars()
            .next()
            .is_none_or(is_extraction_boundary)
}

fn is_extraction_boundary(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '=' | '\'' | '"' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | ';' | ':'
        )
}

fn token_snippet(token: &str) -> String {
    if token.len() <= 20 {
        escape_for_terminal(token)
    } else {
        let snippet = token.chars().take(17).collect::<String>();
        format!("{}...", escape_for_terminal(&snippet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(value: &str) -> String {
        URL_SAFE_NO_PAD.encode(value)
    }

    fn token() -> String {
        format!(
            "{}.{}.",
            segment(r#"{"alg":"none"}"#),
            segment(r#"{"sub":"Troy Barnes"}"#)
        )
    }

    #[test]
    fn parses_objects_and_preserves_large_numbers() {
        let token = format!(
            "{}.{}.",
            segment(r#"{"alg":"none"}"#),
            segment(r#"{"id":9007199254740993}"#)
        );
        let parsed = parse_token(&token).expect("parse token");
        assert_eq!(parsed.claims["id"].to_string(), "9007199254740993");
    }

    #[test]
    fn extracts_from_common_wrappers_but_not_words() {
        let token = token();
        for input in [
            format!("Bearer {token}"),
            format!("session={token}; HttpOnly"),
            format!(r#"{{"access_token":"{token}"}}"#),
        ] {
            assert_eq!(
                resolve_token(&input, false).expect("extract JWT").raw,
                token
            );
        }
        assert!(resolve_token(&format!("prefix{token}suffix"), false).is_err());
        assert!(resolve_token(&format!("Bearer {token}"), true).is_err());
    }

    #[test]
    fn rejects_non_objects_invalid_utf8_and_noncanonical_base64() {
        let array = format!("{}.{}.", segment("[]"), segment("{}"));
        assert_eq!(
            parse_token(&array).expect_err("array header").to_string(),
            "token header is not a JSON object"
        );

        let invalid_utf8 = format!(
            "{}.e30.",
            URL_SAFE_NO_PAD.encode([b'{', b'"', 0xff, b'"', b'}'])
        );
        assert!(
            parse_token(&invalid_utf8)
                .expect_err("invalid UTF-8")
                .to_string()
                .contains("JSON segment is not valid UTF-8")
        );

        assert!(decode_base64_url("Zh").is_err(), "non-zero trailing bits");
    }

    #[test]
    fn unicode_snippets_do_not_panic() {
        let error = parse_token("这是没有JWT的中文文本测试一下看看会不会崩溃啊啊啊")
            .expect_err("invalid token");
        assert!(error.to_string().ends_with("...)"));
    }
}
