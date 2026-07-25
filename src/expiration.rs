use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::time_claims::{classify_time_claim, TimeClaim};

pub fn check_expiration(claims: &Map<String, Value>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64);

    println!("EXPIRATION:");
    match classify_time_claim(claims, "exp") {
        TimeClaim::Valid(exp) if now >= exp => println!(
            "Token expired at {} ({} seconds ago)",
            format_timestamp(exp),
            now - exp
        ),
        TimeClaim::Valid(exp) => println!(
            "Token expires at {} ({} seconds from now)",
            format_timestamp(exp),
            exp - now
        ),
        TimeClaim::Absent => println!("No expiration claim found"),
        TimeClaim::Invalid => {
            if let Some(value) = claims.get("exp") {
                println!("Unrecognized exp value: {value}");
            }
        }
    }

    match classify_time_claim(claims, "nbf") {
        TimeClaim::Valid(nbf) if now < nbf => println!(
            "Token not valid yet. Valid from {} (in {} seconds)",
            format_timestamp(nbf),
            nbf - now
        ),
        TimeClaim::Valid(nbf) => println!(
            "Token valid since {} ({} seconds ago)",
            format_timestamp(nbf),
            now - nbf
        ),
        TimeClaim::Invalid => {
            if let Some(value) = claims.get("nbf") {
                println!("Unrecognized nbf value: {value}");
            }
        }
        TimeClaim::Absent => {}
    }

    match classify_time_claim(claims, "iat") {
        TimeClaim::Valid(iat) => println!(
            "Issued at: {} ({} seconds ago)",
            format_timestamp(iat),
            now - iat
        ),
        TimeClaim::Invalid => {
            if let Some(value) = claims.get("iat") {
                println!("Unrecognized iat value: {value}");
            }
        }
        TimeClaim::Absent => {}
    }

    println!();
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

    use crate::time_claims::parse_numeric_date;

    #[test]
    fn parses_float_numeric_dates_for_display() {
        assert_eq!(
            Some(1_700_000_000),
            parse_numeric_date(&json!(1_700_000_000.0))
        );
    }
}
