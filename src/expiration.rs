use serde_json::{Map, Value};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::output::Output;
use crate::time_claims::{NumericDate, TimeClaim, UnixTime, classify};

pub fn check(claims: &Map<String, Value>, now: UnixTime, output: &mut Output<'_>) {
    output.stdout_line(format_args!("EXPIRATION:"));
    print_expiration(resolve(claims, "exp", now), output);
    print_not_before(resolve(claims, "nbf", now), output);
    print_issued_at(resolve(claims, "iat", now), output);
    output.stdout_line(format_args!(""));
}

enum Resolved<'a> {
    Past(String, i128),
    Future(String, i128),
    Absent,
    Invalid(&'a Value),
}

fn resolve<'a>(claims: &'a Map<String, Value>, name: &str, now: UnixTime) -> Resolved<'a> {
    match classify(claims, name) {
        TimeClaim::Absent => Resolved::Absent,
        TimeClaim::Invalid(value) => Resolved::Invalid(value),
        TimeClaim::Valid(date) => resolve_date(date, now),
    }
}

fn resolve_date(date: NumericDate, now: UnixTime) -> Resolved<'static> {
    let seconds = date.rounded_seconds();
    let timestamp = format_timestamp(seconds);
    if date.is_after(now) {
        Resolved::Future(
            timestamp,
            seconds.saturating_sub(now.whole_seconds()).max(0),
        )
    } else {
        Resolved::Past(
            timestamp,
            now.whole_seconds().saturating_sub(seconds).max(0),
        )
    }
}

fn format_timestamp(timestamp: i128) -> String {
    let Ok(timestamp) = i64::try_from(timestamp) else {
        return timestamp.to_string();
    };
    let Ok(date) = OffsetDateTime::from_unix_timestamp(timestamp) else {
        return timestamp.to_string();
    };
    date.format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.to_string())
}

fn print_expiration(claim: Resolved<'_>, output: &mut Output<'_>) {
    match claim {
        Resolved::Past(at, seconds) => {
            output.stdout_line(format_args!(
                "Token expired at {at} ({seconds} seconds ago)"
            ));
        }
        Resolved::Future(at, seconds) => output.stdout_line(format_args!(
            "Token expires at {at} ({seconds} seconds from now)"
        )),
        Resolved::Absent => output.stdout_line(format_args!("No expiration claim found")),
        Resolved::Invalid(value) => {
            output.stdout_line(format_args!("Unrecognized exp value: {value}"));
        }
    }
}

fn print_not_before(claim: Resolved<'_>, output: &mut Output<'_>) {
    match claim {
        Resolved::Past(at, seconds) => output.stdout_line(format_args!(
            "Token valid since {at} ({seconds} seconds ago)"
        )),
        Resolved::Future(at, seconds) => output.stdout_line(format_args!(
            "Token not valid yet. Valid from {at} (in {seconds} seconds)"
        )),
        Resolved::Absent => {}
        Resolved::Invalid(value) => {
            output.stdout_line(format_args!("Unrecognized nbf value: {value}"));
        }
    }
}

fn print_issued_at(claim: Resolved<'_>, output: &mut Output<'_>) {
    match claim {
        Resolved::Past(at, seconds) => {
            output.stdout_line(format_args!("Issued at: {at} ({seconds} seconds ago)"));
        }
        Resolved::Future(at, seconds) => {
            output.stdout_line(format_args!("Issued at: {at} ({seconds} seconds from now)"));
        }
        Resolved::Absent => {}
        Resolved::Invalid(value) => {
            output.stdout_line(format_args!("Unrecognized iat value: {value}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn reports_all_time_claims_in_utc() {
        let claims = json!({
            "exp": 1_699_999_900,
            "nbf": 1_699_999_800,
            "iat": 1_700_000_100,
        });
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut output = Output::new(&mut stdout, &mut stderr);
        check(
            claims.as_object().expect("claims object"),
            UnixTime::new(1_700_000_000, 0),
            &mut output,
        );
        drop(output);
        let output = String::from_utf8(stdout).expect("UTF-8 output");

        assert!(output.contains("2023-11-14T22:11:40Z (100 seconds ago)"));
        assert!(output.contains("2023-11-14T22:10:00Z (200 seconds ago)"));
        assert!(output.contains("2023-11-14T22:15:00Z (100 seconds from now)"));
    }

    #[test]
    fn unsupported_timestamp_ranges_remain_numeric() {
        assert_eq!(format_timestamp(i128::from(u64::MAX)), u64::MAX.to_string());
        assert_eq!(format_timestamp(i128::from(i64::MIN)), i64::MIN.to_string());
    }
}
