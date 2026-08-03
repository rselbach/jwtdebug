use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::time_claims::{classify_time_claim, TimeClaim};

pub fn check_expiration(claims: &Map<String, Value>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let now_wide = i128::from(now.as_secs());

    println!("EXPIRATION:");
    match classify_time_claim(claims, "exp") {
        TimeClaim::Valid(exp) if !exp.is_after_unix_time(now) => println!(
            "Token expired at {} ({} seconds ago)",
            format_timestamp(exp.rounded_seconds()),
            (now_wide - exp.rounded_seconds()).max(0)
        ),
        TimeClaim::Valid(exp) => println!(
            "Token expires at {} ({} seconds from now)",
            format_timestamp(exp.rounded_seconds()),
            (exp.rounded_seconds() - now_wide).max(0)
        ),
        TimeClaim::Absent => println!("No expiration claim found"),
        TimeClaim::Invalid => {
            if let Some(value) = claims.get("exp") {
                println!("Unrecognized exp value: {value}");
            }
        }
    }

    match classify_time_claim(claims, "nbf") {
        TimeClaim::Valid(nbf) if nbf.is_after_unix_time(now) => println!(
            "Token not valid yet. Valid from {} (in {} seconds)",
            format_timestamp(nbf.rounded_seconds()),
            (nbf.rounded_seconds() - now_wide).max(0)
        ),
        TimeClaim::Valid(nbf) => println!(
            "Token valid since {} ({} seconds ago)",
            format_timestamp(nbf.rounded_seconds()),
            (now_wide - nbf.rounded_seconds()).max(0)
        ),
        TimeClaim::Invalid => {
            if let Some(value) = claims.get("nbf") {
                println!("Unrecognized nbf value: {value}");
            }
        }
        TimeClaim::Absent => {}
    }

    match classify_time_claim(claims, "iat") {
        TimeClaim::Valid(iat) if iat.is_after_unix_time(now) => println!(
            "Issued at: {} ({} seconds from now)",
            format_timestamp(iat.rounded_seconds()),
            (iat.rounded_seconds() - now_wide).max(0)
        ),
        TimeClaim::Valid(iat) => println!(
            "Issued at: {} ({} seconds ago)",
            format_timestamp(iat.rounded_seconds()),
            (now_wide - iat.rounded_seconds()).max(0)
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

fn format_timestamp(timestamp: i128) -> String {
    let Ok(timestamp) = i64::try_from(timestamp) else {
        return timestamp.to_string();
    };
    let Ok(datetime) = OffsetDateTime::from_unix_timestamp(timestamp) else {
        return timestamp.to_string();
    };
    // Resolve the offset in effect at the instant being formatted, not the one
    // in effect now, so timestamps across a DST boundary keep their own offset.
    let offset = UtcOffset::local_offset_at(datetime).unwrap_or(UtcOffset::UTC);
    // Shifting into a non-UTC offset moves the wall-clock instant and can push
    // a boundary year past the supported range, which to_offset panics on.
    // checked_to_offset is no help: it debug-asserts the year before it can
    // report the overflow, so screen the shifted instant here instead.
    let shifted = timestamp.saturating_add(i64::from(offset.whole_seconds()));
    if OffsetDateTime::from_unix_timestamp(shifted).is_err() {
        return timestamp.to_string();
    }

    datetime
        .to_offset(offset)
        .format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.to_string())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::time_claims::{parse_numeric_date, NumericDate};

    #[test]
    fn parses_float_numeric_dates_for_display() {
        assert_eq!(
            Some(NumericDate::Fractional(1_700_000_000.0)),
            parse_numeric_date(&json!(1_700_000_000.0))
        );
    }
}
