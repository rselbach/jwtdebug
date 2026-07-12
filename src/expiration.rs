use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

const MIN_TIMESTAMP: i64 = 946_684_800;
const MAX_TIMESTAMP: i64 = 4_102_444_800;

pub fn check_expiration(claims: &Map<String, Value>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64);

    println!("EXPIRATION:");
    match time_claim(claims, "exp") {
        Some(exp) if now >= exp => println!(
            "Token expired at {} ({} seconds ago)",
            format_timestamp(exp),
            now - exp
        ),
        Some(exp) => println!(
            "Token expires at {} ({} seconds from now)",
            format_timestamp(exp),
            exp - now
        ),
        None if !claims.contains_key("exp") => println!("No expiration claim found"),
        None => {}
    }

    match time_claim(claims, "nbf") {
        Some(nbf) if now < nbf => println!(
            "Token not valid yet. Valid from {} (in {} seconds)",
            format_timestamp(nbf),
            nbf - now
        ),
        Some(nbf) => println!(
            "Token valid since {} ({} seconds ago)",
            format_timestamp(nbf),
            now - nbf
        ),
        None => {}
    }

    if let Some(iat) = time_claim(claims, "iat") {
        println!(
            "Issued at: {} ({} seconds ago)",
            format_timestamp(iat),
            now - iat
        );
    }

    println!();
}

fn time_claim(claims: &Map<String, Value>, name: &str) -> Option<i64> {
    let value = claims.get(name)?;
    let timestamp = try_parse_timestamp(value);
    if timestamp.is_none() {
        println!("Unrecognized {name} value: {value}");
    }
    timestamp
}

fn try_parse_timestamp(value: &Value) -> Option<i64> {
    let timestamp = match value {
        Value::Number(number) => number.as_i64()?,
        Value::String(s) => parse_rfc3339_timestamp(s).or_else(|| s.parse::<i64>().ok())?,
        _ => return None,
    };

    if !(MIN_TIMESTAMP..=MAX_TIMESTAMP).contains(&timestamp) {
        return None;
    }

    Some(timestamp)
}

fn parse_rfc3339_timestamp(s: &str) -> Option<i64> {
    OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(|datetime| datetime.unix_timestamp())
}

fn format_timestamp(timestamp: i64) -> String {
    let Ok(datetime) = OffsetDateTime::from_unix_timestamp(timestamp) else {
        return timestamp.to_string();
    };
    let offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);

    datetime
        .to_offset(offset)
        .format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_numeric_string_epoch() {
        assert_eq!(
            Some(1_700_000_000),
            try_parse_timestamp(&json!("1700000000"))
        );
    }

    #[test]
    fn parses_rfc3339_utc() {
        assert_eq!(
            Some(1_136_214_245),
            try_parse_timestamp(&json!("2006-01-02T15:04:05Z"))
        );
    }

    #[test]
    fn rejects_out_of_range_timestamp() {
        assert_eq!(None, try_parse_timestamp(&json!(100)));
    }
}
