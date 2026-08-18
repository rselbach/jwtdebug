use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NumericDate {
    Integer(i128),
    Fractional(f64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixTime {
    seconds: i128,
    nanoseconds: u32,
}

impl UnixTime {
    pub fn new(seconds: i128, nanoseconds: u32) -> Self {
        Self {
            seconds,
            nanoseconds,
        }
    }

    pub fn now() -> Self {
        let now = OffsetDateTime::now_utc();
        Self::new(i128::from(now.unix_timestamp()), now.nanosecond())
    }

    pub fn add_seconds(self, seconds: i128) -> Self {
        Self::new(self.seconds.saturating_add(seconds), self.nanoseconds)
    }

    pub fn whole_seconds(self) -> i128 {
        self.seconds
    }

    fn as_f64(self) -> f64 {
        self.seconds as f64 + f64::from(self.nanoseconds) / 1_000_000_000.0
    }
}

impl NumericDate {
    pub fn is_before(self, timestamp: UnixTime) -> bool {
        match self {
            Self::Integer(value) => {
                value < timestamp.seconds
                    || (value == timestamp.seconds && timestamp.nanoseconds != 0)
            }
            Self::Fractional(value) => value < timestamp.as_f64(),
        }
    }

    pub fn is_after(self, timestamp: UnixTime) -> bool {
        match self {
            Self::Integer(value) => value > timestamp.seconds,
            Self::Fractional(value) => value > timestamp.as_f64(),
        }
    }

    pub fn rounded_seconds(self) -> i128 {
        match self {
            Self::Integer(value) => value,
            Self::Fractional(value) => value.round() as i128,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum TimeClaim<'a> {
    Absent,
    Invalid(&'a Value),
    Valid(NumericDate),
}

pub fn classify<'a>(claims: &'a serde_json::Map<String, Value>, name: &str) -> TimeClaim<'a> {
    match claims.get(name) {
        None => TimeClaim::Absent,
        Some(raw) => parse_numeric_date(raw)
            .map(TimeClaim::Valid)
            .unwrap_or(TimeClaim::Invalid(raw)),
    }
}

pub fn parse_numeric_date(value: &Value) -> Option<NumericDate> {
    match value {
        Value::Number(number) => parse_json_number(&number.to_string()),
        Value::String(value) => {
            if let Ok(timestamp) = OffsetDateTime::parse(value, &Rfc3339) {
                return Some(NumericDate::Integer(i128::from(timestamp.unix_timestamp())));
            }
            if let Ok(timestamp) = value.parse::<i64>() {
                return Some(NumericDate::Integer(i128::from(timestamp)));
            }
            parse_fraction(value)
        }
        _ => None,
    }
}

fn parse_json_number(value: &str) -> Option<NumericDate> {
    if !value.contains(['.', 'e', 'E']) {
        let timestamp = value.parse::<i128>().ok()?;
        if timestamp < i128::from(i64::MIN) || timestamp > i128::from(u64::MAX) {
            return None;
        }
        return Some(NumericDate::Integer(timestamp));
    }
    parse_fraction(value)
}

fn parse_fraction(value: &str) -> Option<NumericDate> {
    let timestamp = value.parse::<f64>().ok()?;
    (timestamp.is_finite() && timestamp >= i64::MIN as f64 && timestamp < u64::MAX as f64)
        .then_some(NumericDate::Fractional(timestamp))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_supported_numeric_date_forms_exactly() {
        for (value, expected) in [
            (json!(1_700_000_000), NumericDate::Integer(1_700_000_000)),
            (json!(u64::MAX), NumericDate::Integer(i128::from(u64::MAX))),
            (json!(-1), NumericDate::Integer(-1)),
            (
                json!(1_700_000_000.5),
                NumericDate::Fractional(1_700_000_000.5),
            ),
            (
                json!("1700000000.5"),
                NumericDate::Fractional(1_700_000_000.5),
            ),
            (
                json!("2006-01-02T15:04:05Z"),
                NumericDate::Integer(1_136_214_245),
            ),
        ] {
            assert_eq!(parse_numeric_date(&value), Some(expected));
        }
    }

    #[test]
    fn rejects_out_of_range_and_non_numeric_values() {
        let too_large: Value = serde_json::from_str("18446744073709551616").expect("JSON number");
        let too_small: Value = serde_json::from_str("-9223372036854775809").expect("JSON number");
        for value in [
            too_large,
            too_small,
            json!("inf"),
            json!(true),
            json!(null),
            json!([]),
        ] {
            assert_eq!(parse_numeric_date(&value), None, "value: {value}");
        }
    }

    #[test]
    fn compares_subsecond_boundaries() {
        let now = UnixTime::new(1_700_000_000, 750_000_000);
        assert!(NumericDate::Fractional(1_700_000_000.5).is_before(now));
        assert!(NumericDate::Fractional(1_700_000_000.9).is_after(now));
        assert!(NumericDate::Integer(1_700_000_000).is_before(now));
        assert!(NumericDate::Integer(1_700_000_001).is_after(now));
    }
}
