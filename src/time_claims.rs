use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Parsed representation of a JWT NumericDate-like value.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericDate {
    /// Whole seconds from the Unix epoch.
    Integer(i128),
    /// Fractional seconds from the Unix epoch.
    Fractional(f64),
}

impl NumericDate {
    /// Return whether this date is before an integer Unix timestamp.
    pub fn is_before(self, timestamp: i64) -> bool {
        match self {
            Self::Integer(value) => value < i128::from(timestamp),
            Self::Fractional(value) => value < timestamp as f64,
        }
    }

    /// Return whether this date is after an integer Unix timestamp.
    pub fn is_after(self, timestamp: i64) -> bool {
        match self {
            Self::Integer(value) => value > i128::from(timestamp),
            Self::Fractional(value) => value > timestamp as f64,
        }
    }

    /// Round to the nearest whole second for human-readable display.
    pub fn rounded_seconds(self) -> i128 {
        match self {
            Self::Integer(value) => value,
            Self::Fractional(value) => value.round() as i128,
        }
    }
}

/// Result of reading a JWT time claim (`exp`, `nbf`, `iat`).
#[derive(Debug, Clone, PartialEq)]
pub enum TimeClaim {
    /// Claim key is absent from the payload.
    Absent,
    /// Claim is present but not a usable NumericDate (or RFC3339 string).
    Invalid,
    /// Claim parsed to a NumericDate-like value.
    Valid(NumericDate),
}

/// Classify a named time claim from a JWT claims object.
pub fn classify_time_claim(claims: &serde_json::Map<String, Value>, name: &str) -> TimeClaim {
    match claims.get(name) {
        None => TimeClaim::Absent,
        Some(value) => match parse_numeric_date(value) {
            Some(timestamp) => TimeClaim::Valid(timestamp),
            None => TimeClaim::Invalid,
        },
    }
}

/// Parse a JWT NumericDate-like value.
///
/// Accepts JSON numbers (including fractional values), decimal integer strings,
/// and RFC3339 timestamps. Rejects non-finite numbers, floats outside the
/// representable signed timestamp range, and other JSON types.
pub fn parse_numeric_date(value: &Value) -> Option<NumericDate> {
    match value {
        Value::Number(number) => {
            if let Some(timestamp) = number.as_i64() {
                return Some(NumericDate::Integer(i128::from(timestamp)));
            }
            if let Some(timestamp) = number.as_u64() {
                return Some(NumericDate::Integer(i128::from(timestamp)));
            }
            let timestamp = number.as_f64()?;
            if !timestamp.is_finite() {
                return None;
            }
            if timestamp < i64::MIN as f64 || timestamp >= -(i64::MIN as f64) {
                return None;
            }
            Some(NumericDate::Fractional(timestamp))
        }
        Value::String(s) => parse_rfc3339_timestamp(s)
            .or_else(|| s.parse::<i64>().ok())
            .map(i128::from)
            .map(NumericDate::Integer),
        _ => None,
    }
}

fn parse_rfc3339_timestamp(s: &str) -> Option<i64> {
    OffsetDateTime::parse(s, &Rfc3339)
        .ok()
        .map(|datetime| datetime.unix_timestamp())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_integer_number() {
        assert_eq!(
            Some(NumericDate::Integer(1_700_000_000)),
            parse_numeric_date(&json!(1_700_000_000))
        );
    }

    #[test]
    fn parses_maximum_unsigned_integer() {
        assert_eq!(
            Some(NumericDate::Integer(i128::from(u64::MAX))),
            parse_numeric_date(&json!(u64::MAX))
        );
    }

    #[test]
    fn parses_whole_float_number() {
        assert_eq!(
            Some(NumericDate::Fractional(1_700_000_000.0)),
            parse_numeric_date(&json!(1_700_000_000.0))
        );
    }

    #[test]
    fn preserves_fractional_float() {
        assert_eq!(
            Some(NumericDate::Fractional(1_700_000_000.5)),
            parse_numeric_date(&json!(1_700_000_000.5))
        );
    }

    #[test]
    fn parses_numeric_string_epoch() {
        assert_eq!(
            Some(NumericDate::Integer(1_700_000_000)),
            parse_numeric_date(&json!("1700000000"))
        );
    }

    #[test]
    fn parses_rfc3339_utc() {
        assert_eq!(
            Some(NumericDate::Integer(1_136_214_245)),
            parse_numeric_date(&json!("2006-01-02T15:04:05Z"))
        );
    }

    #[test]
    fn parses_pre_year_2000_timestamps() {
        assert_eq!(Some(NumericDate::Integer(0)), parse_numeric_date(&json!(0)));
        assert_eq!(
            Some(NumericDate::Integer(-1)),
            parse_numeric_date(&json!(-1))
        );
    }

    #[test]
    fn rejects_non_numeric_types() {
        assert_eq!(None, parse_numeric_date(&json!(true)));
        assert_eq!(None, parse_numeric_date(&json!(null)));
        assert_eq!(None, parse_numeric_date(&json!([])));
        assert_eq!(None, parse_numeric_date(&json!({})));
    }

    #[test]
    fn classify_distinguishes_absent_invalid_valid() {
        let claims = json!({ "exp": true, "nbf": 1_700_000_000 })
            .as_object()
            .cloned()
            .expect("object");
        assert_eq!(TimeClaim::Absent, classify_time_claim(&claims, "iat"));
        assert_eq!(TimeClaim::Invalid, classify_time_claim(&claims, "exp"));
        assert_eq!(
            TimeClaim::Valid(NumericDate::Integer(1_700_000_000)),
            classify_time_claim(&claims, "nbf")
        );
    }
}
