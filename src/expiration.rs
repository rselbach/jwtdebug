use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::output::Output;
use crate::time_claims::{classify_time_claim, TimeClaim};

pub fn check_expiration(claims: &Map<String, Value>, output: &mut Output<'_>) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    output.stdout_line(format_args!("EXPIRATION:"));
    match resolve(claims, "exp", now) {
        Resolved::Past(at, ago) => {
            output.stdout_line(format_args!("Token expired at {at} ({ago} seconds ago)"));
        }
        Resolved::Future(at, until) => {
            output.stdout_line(format_args!(
                "Token expires at {at} ({until} seconds from now)"
            ));
        }
        Resolved::Absent => output.stdout_line(format_args!("No expiration claim found")),
        Resolved::Unrecognized(value) => {
            output.stdout_line(format_args!("Unrecognized exp value: {value}"));
        }
    }

    match resolve(claims, "nbf", now) {
        Resolved::Past(at, ago) => {
            output.stdout_line(format_args!("Token valid since {at} ({ago} seconds ago)"));
        }
        Resolved::Future(at, until) => {
            output.stdout_line(format_args!(
                "Token not valid yet. Valid from {at} (in {until} seconds)"
            ));
        }
        Resolved::Absent => {}
        Resolved::Unrecognized(value) => {
            output.stdout_line(format_args!("Unrecognized nbf value: {value}"));
        }
    }

    match resolve(claims, "iat", now) {
        Resolved::Past(at, ago) => {
            output.stdout_line(format_args!("Issued at: {at} ({ago} seconds ago)"));
        }
        Resolved::Future(at, until) => {
            output.stdout_line(format_args!("Issued at: {at} ({until} seconds from now)"));
        }
        Resolved::Absent => {}
        Resolved::Unrecognized(value) => {
            output.stdout_line(format_args!("Unrecognized iat value: {value}"));
        }
    }

    output.stdout_line(format_args!(""));
}

/// A time claim reduced to what the report needs: a formatted UTC timestamp
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
    datetime
        .format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.to_string())
}
