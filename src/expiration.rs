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
    print_time_claim(
        "exp",
        claims,
        |timestamp| {
            if now > timestamp {
                println!(
                    "Token expired at {} ({} seconds ago)",
                    format_timestamp(timestamp),
                    now - timestamp
                );
                return;
            }

            println!(
                "Token expires at {} ({} seconds from now)",
                format_timestamp(timestamp),
                timestamp - now
            );
        },
        Some(|| println!("No expiration claim found")),
    );

    print_time_claim(
        "nbf",
        claims,
        |timestamp| {
            if now < timestamp {
                println!(
                    "Token not valid yet. Valid from {} (in {} seconds)",
                    format_timestamp(timestamp),
                    timestamp - now
                );
                return;
            }

            println!(
                "Token valid since {} ({} seconds ago)",
                format_timestamp(timestamp),
                now - timestamp
            );
        },
        None::<fn()>,
    );

    print_time_claim(
        "iat",
        claims,
        |timestamp| {
            println!(
                "Issued at: {} ({} seconds ago)",
                format_timestamp(timestamp),
                now - timestamp
            );
        },
        None::<fn()>,
    );

    println!();
}

fn print_time_claim<F, M>(
    name: &str,
    claims: &Map<String, Value>,
    on_found: F,
    on_missing: Option<M>,
) where
    F: FnOnce(i64),
    M: FnOnce(),
{
    let Some(value) = claims.get(name) else {
        if let Some(on_missing) = on_missing {
            on_missing();
        }
        return;
    };

    match try_parse_timestamp(value) {
        Some(timestamp) => on_found(timestamp),
        None => println!("Unrecognized {name} value: {value}"),
    }
}

fn try_parse_timestamp(value: &Value) -> Option<i64> {
    let timestamp = match value {
        Value::Number(number) => number
            .as_i64()
            .or_else(|| number.as_u64().and_then(|n| n.try_into().ok()))?,
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
