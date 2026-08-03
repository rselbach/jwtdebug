use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{OffsetDateTime, UtcOffset};

use crate::time_claims::{classify_time_claim, TimeClaim};

pub fn check_expiration(claims: &Map<String, Value>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    println!("EXPIRATION:");
    match resolve(claims, "exp", now) {
        Resolved::Past(at, ago) => println!("Token expired at {at} ({ago} seconds ago)"),
        Resolved::Future(at, until) => {
            println!("Token expires at {at} ({until} seconds from now)")
        }
        Resolved::Absent => println!("No expiration claim found"),
        Resolved::Unrecognized(value) => println!("Unrecognized exp value: {value}"),
    }

    match resolve(claims, "nbf", now) {
        Resolved::Past(at, ago) => println!("Token valid since {at} ({ago} seconds ago)"),
        Resolved::Future(at, until) => {
            println!("Token not valid yet. Valid from {at} (in {until} seconds)")
        }
        Resolved::Absent => {}
        Resolved::Unrecognized(value) => println!("Unrecognized nbf value: {value}"),
    }

    match resolve(claims, "iat", now) {
        Resolved::Past(at, ago) => println!("Issued at: {at} ({ago} seconds ago)"),
        Resolved::Future(at, until) => println!("Issued at: {at} ({until} seconds from now)"),
        Resolved::Absent => {}
        Resolved::Unrecognized(value) => println!("Unrecognized iat value: {value}"),
    }

    println!();
}

/// A time claim reduced to what the report needs: a formatted local timestamp
/// and its non-negative distance from now, in seconds.
enum Resolved<'a> {
    Past(String, i128),
    Future(String, i128),
    Absent,
    Unrecognized(&'a Value),
}

fn resolve<'a>(claims: &'a Map<String, Value>, name: &str, now: Duration) -> Resolved<'a> {
    let now_wide = i128::from(now.as_secs());
    match classify_time_claim(claims, name) {
        TimeClaim::Absent => Resolved::Absent,
        TimeClaim::Invalid(value) => Resolved::Unrecognized(value),
        TimeClaim::Valid(claim) => {
            let seconds = claim.rounded_seconds();
            let at = format_timestamp(seconds);
            if claim.is_after_unix_time(now) {
                Resolved::Future(at, (seconds - now_wide).max(0))
            } else {
                Resolved::Past(at, (now_wide - seconds).max(0))
            }
        }
    }
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
