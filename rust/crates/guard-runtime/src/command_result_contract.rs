//! The v2 command-result contract (`contracts/guard-cloud-review/v2/command-result.json`)
//! for the exact Review result `command-result --stdin` posts.

use serde_json::{json, Map, Value};

use super::{CONTRACT_INVALID, PROTOCOL_VERSION};

const CONTRACT_VERSION: &str = "guard-cloud-review-command-result-v2";
const MAX_REASON_CHARS: usize = 128;
const MAX_OPAQUE_ID_CHARS: usize = 256;

pub(super) struct Fields {
    pub(super) correlation_id: String,
    pub(super) local_request_id: String,
    pub(super) receipt_id: String,
    pub(super) application_status: String,
    pub(super) application_reason: Option<String>,
    pub(super) continuation_status: String,
    pub(super) continuation_reason: Option<String>,
    pub(super) application_updated_at: String,
    pub(super) continuation_updated_at: String,
}

pub(super) fn contract_result(fields: Fields) -> Result<Map<String, Value>, &'static str> {
    validate(&fields)?;
    let mut result = Map::new();
    result.insert(
        "applicationReason".to_owned(),
        json!(fields.application_reason),
    );
    result.insert(
        "applicationStatus".to_owned(),
        json!(fields.application_status),
    );
    result.insert(
        "applicationUpdatedAt".to_owned(),
        json!(fields.application_updated_at),
    );
    result.insert(
        "continuationReason".to_owned(),
        json!(fields.continuation_reason),
    );
    result.insert(
        "continuationStatus".to_owned(),
        json!(fields.continuation_status),
    );
    result.insert(
        "continuationUpdatedAt".to_owned(),
        json!(fields.continuation_updated_at),
    );
    result.insert("contractVersion".to_owned(), json!(CONTRACT_VERSION));
    result.insert("correlationId".to_owned(), json!(fields.correlation_id));
    result.insert("localRequestId".to_owned(), json!(fields.local_request_id));
    result.insert("protocolVersion".to_owned(), json!(PROTOCOL_VERSION));
    result.insert("receiptId".to_owned(), json!(fields.receipt_id));
    Ok(result)
}

/// The rules `command-result.json` states: bounded opaque ids and reasons, a
/// null reason on `applied`, a reason on every rejected or failed status, and
/// RFC 3339 timestamps.
fn validate(fields: &Fields) -> Result<(), &'static str> {
    let ids = [
        &fields.correlation_id,
        &fields.local_request_id,
        &fields.receipt_id,
    ];
    if !ids.iter().all(|id| opaque_id(id)) {
        return Err(CONTRACT_INVALID);
    }
    let reasons = [&fields.application_reason, &fields.continuation_reason];
    if reasons.iter().any(|reason| {
        reason
            .as_ref()
            .is_some_and(|text| text.chars().count() > MAX_REASON_CHARS)
    }) {
        return Err(CONTRACT_INVALID);
    }
    let reason_fits = match fields.application_status.as_str() {
        "applied" => fields.application_reason.is_none(),
        "rejected_stale" | "rejected_binding" | "failed_retryable" | "failed_terminal" => {
            fields.application_reason.is_some()
        }
        _ => true,
    };
    if !reason_fits {
        return Err(CONTRACT_INVALID);
    }
    if !rfc3339(&fields.application_updated_at) || !rfc3339(&fields.continuation_updated_at) {
        return Err(CONTRACT_INVALID);
    }
    Ok(())
}

/// `^[A-Za-z0-9][A-Za-z0-9._:-]*$`, one to 256 characters.
fn opaque_id(value: &str) -> bool {
    let mut chars = value.chars();
    value.len() <= MAX_OPAQUE_ID_CHARS
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` naming a real calendar day, the
/// shape `_is_rfc3339_date_time` accepted.
pub(super) fn rfc3339(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || !value.is_ascii() {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let slice = bytes.get(range)?;
        slice.iter().all(u8::is_ascii_digit).then(|| {
            slice
                .iter()
                .fold(0, |acc, b| acc * 10 + u32::from(b - b'0'))
        })
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators
        .iter()
        .any(|(index, byte)| bytes[*index] != *byte)
    {
        return false;
    }
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
        digits(17..19),
    ) else {
        return false;
    };
    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return false;
    }
    let mut rest = &value[19..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let length = fraction.bytes().take_while(u8::is_ascii_digit).count();
        if length == 0 {
            return false;
        }
        rest = &fraction[length..];
    }
    if rest == "Z" {
        return true;
    }
    let offset = rest.as_bytes();
    offset.len() == 6
        && matches!(offset[0], b'+' | b'-')
        && offset[3] == b':'
        && offset[1..3]
            .iter()
            .chain(&offset[4..6])
            .all(u8::is_ascii_digit)
        && (offset[1] - b'0') * 10 + (offset[2] - b'0') <= 23
        && offset[4] <= b'5'
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}
