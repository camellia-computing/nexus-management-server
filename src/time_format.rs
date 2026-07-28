use std::{
    borrow::Cow,
    error::Error,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::{Map, Value};
use time::{
    Date, Duration, OffsetDateTime, Time, format_description::well_known::Rfc3339,
    macros::format_description,
};

type TimeResult<T> = std::result::Result<T, Box<dyn Error>>;

const SECONDS_PER_DAY: i64 = 24 * 60 * 60;

const TIME_KEYS: &[&str] = &[
    "created_at",
    "updated_at",
    "expires_at",
    "issued_at",
    "refresh_after",
    "last_seen_at",
    "last_redeemed_at",
    "pending_activation_expires_at",
    "consumed_at",
    "occurred_at",
    "server_unix",
    "createdAt",
    "updatedAt",
    "expiresAt",
    "issuedAt",
    "refreshAfter",
    "lastSeenAt",
    "lastRedeemedAt",
    "pendingActivationExpiresAt",
    "consumedAt",
    "occurredAt",
    "serverUnix",
];

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

pub fn format_unix_seconds(unix: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(unix) {
        Ok(instant) => instant
            .format(&Rfc3339)
            .unwrap_or_else(|_| format!("invalid-unix-timestamp:{unix}")),
        Err(_) => format!("invalid-unix-timestamp:{unix}"),
    }
}

pub fn parse_absolute_time(value: &str) -> TimeResult<i64> {
    parse_time_input(value.trim())
}

pub fn parse_expiry_time(value: &str, now: i64) -> TimeResult<i64> {
    let trimmed = value.trim();
    if let Some(duration) = parse_relative_duration(trimmed)? {
        return Ok(now.saturating_add(duration.whole_seconds()));
    }
    parse_time_input(trimmed)
}

pub fn parse_optional_expiry_time(value: &str, now: i64) -> TimeResult<Option<i64>> {
    let trimmed = value.trim();
    if is_none_time(trimmed) {
        return Ok(None);
    }
    Ok(Some(parse_expiry_time(trimmed, now)?))
}

pub(crate) fn parse_relative_duration_seconds(value: &str) -> Result<Option<i64>, Box<dyn Error>> {
    parse_relative_duration(value.trim())
        .map(|duration| duration.map(|duration| duration.whole_seconds()))
}

pub fn with_human_times<T: serde::Serialize>(value: &T) -> TimeResult<Value> {
    let mut value = serde_json::to_value(value)?;
    add_human_times(&mut value);
    Ok(value)
}

fn parse_time_input(value: &str) -> TimeResult<i64> {
    if value.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok(value.parse()?);
    }
    if let Ok(datetime) = OffsetDateTime::parse(value, &Rfc3339) {
        return Ok(datetime.unix_timestamp());
    }
    if let Ok(datetime) = parse_space_separated_utc(value) {
        return Ok(datetime.unix_timestamp());
    }
    if let Ok(date) = parse_utc_date(value) {
        return Ok(date.with_time(Time::MIDNIGHT).assume_utc().unix_timestamp());
    }
    Err(format!(
        "invalid time '{value}'; use RFC3339 like 2027-01-01T00:00:00Z, UTC date YYYY-MM-DD, or Unix seconds"
    )
    .into())
}

fn parse_utc_date(value: &str) -> TimeResult<Date> {
    let format = format_description!("[year]-[month]-[day]");
    Ok(Date::parse(value, format)?)
}

fn parse_space_separated_utc(value: &str) -> TimeResult<OffsetDateTime> {
    let format = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");
    let primitive = time::PrimitiveDateTime::parse(value, format)?;
    Ok(primitive.assume_utc())
}

fn parse_relative_duration(value: &str) -> TimeResult<Option<Duration>> {
    let raw = value.strip_prefix('+').unwrap_or(value);
    if raw.is_empty() || raw.chars().all(|ch| ch.is_ascii_digit()) {
        return Ok(None);
    }
    let split_at = raw
        .find(|ch: char| !ch.is_ascii_digit())
        .ok_or_else(|| format!("invalid relative duration '{value}'"))?;
    let (amount, unit) = raw.split_at(split_at);
    if amount.is_empty() {
        return Ok(None);
    }
    let amount: i64 = amount.parse()?;
    if !unit.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Ok(None);
    }
    let seconds = match unit {
        "s" | "sec" | "secs" | "second" | "seconds" => amount,
        "m" | "min" | "mins" | "minute" | "minutes" => amount.saturating_mul(60),
        "h" | "hr" | "hrs" | "hour" | "hours" => amount.saturating_mul(60 * 60),
        "d" | "day" | "days" => amount.saturating_mul(SECONDS_PER_DAY),
        "w" | "week" | "weeks" => amount.saturating_mul(7 * SECONDS_PER_DAY),
        _ => return Err(format!("invalid relative duration unit '{unit}'").into()),
    };
    Ok(Some(Duration::seconds(seconds)))
}

fn add_human_times(value: &mut Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                add_human_times(item);
            }
        }
        Value::Object(object) => add_human_times_to_object(object),
        _ => {}
    }
}

fn add_human_times_to_object(object: &mut Map<String, Value>) {
    for value in object.values_mut() {
        add_human_times(value);
    }
    let additions = object
        .iter()
        .filter_map(|(key, value)| {
            if !TIME_KEYS.contains(&key.as_str()) || key.ends_with("Iso") || key.ends_with("_iso") {
                return None;
            }
            let iso_key = iso_key_for(key);
            if object.contains_key(iso_key.as_ref()) {
                return None;
            }
            let iso_value = match value {
                Value::Number(number) => number
                    .as_i64()
                    .map(format_unix_seconds)
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                Value::Null => Value::Null,
                _ => return None,
            };
            Some((iso_key.into_owned(), iso_value))
        })
        .collect::<Vec<_>>();
    object.extend(additions);
}

fn iso_key_for(key: &str) -> Cow<'_, str> {
    if key.contains('_') {
        Cow::Owned(format!("{key}_iso"))
    } else {
        Cow::Owned(format!("{key}Iso"))
    }
}

fn is_none_time(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "none" | "never" | "null" | "-"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_human_and_legacy_time_inputs() {
        assert_eq!(parse_time_input("1798761600").unwrap(), 1_798_761_600);
        assert_eq!(
            parse_time_input("2027-01-01T00:00:00Z").unwrap(),
            1_798_761_600
        );
        assert_eq!(parse_time_input("2027-01-01").unwrap(), 1_798_761_600);
        assert_eq!(
            parse_time_input("2027-01-01 00:00:00").unwrap(),
            1_798_761_600
        );
    }

    #[test]
    fn parses_relative_expiry_inputs() {
        assert_eq!(
            parse_expiry_time("+30d", 1_000).unwrap(),
            1_000 + 30 * SECONDS_PER_DAY
        );
        assert_eq!(
            parse_expiry_time("12h", 1_000).unwrap(),
            1_000 + 12 * 60 * 60
        );
    }

    #[test]
    fn augments_time_fields_without_removing_machine_values() {
        let value = json!({
            "expiresAt": 1_798_761_600,
            "nested": {
                "created_at": 1_798_761_600,
                "last_redeemed_at": 1_798_761_600
            },
            "count": 3
        });
        let augmented = with_human_times(&value).unwrap();
        assert_eq!(augmented["expiresAt"], 1_798_761_600);
        assert_eq!(augmented["expiresAtIso"], "2027-01-01T00:00:00Z");
        assert_eq!(
            augmented["nested"]["created_at_iso"],
            "2027-01-01T00:00:00Z"
        );
        assert_eq!(
            augmented["nested"]["last_redeemed_at_iso"],
            "2027-01-01T00:00:00Z"
        );
        assert!(augmented.get("countIso").is_none());
    }
}
