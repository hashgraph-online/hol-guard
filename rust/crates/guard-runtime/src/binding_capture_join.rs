//! Validate existing capture output and join bounded, keyed capture rows.

use crate::binding_capture_crypto::{
    CaptureSession, CAPTURE_SCHEMA, FINGERPRINT_SCHEME, MAX_BYTES, MAX_RECORDS,
};
use crate::binding_capture_json::{self as json, Json};
use crate::binding_capture_record::{
    canonical_event_name, validated_record, Validated, BINDABLE_CODEX_HOOK_EVENTS,
};

/// Number of valid rows in an existing output, or `None` when the output
/// cannot safely be appended to (`valid_existing_records`).
pub(crate) fn valid_existing_records(
    raw: &[u8],
    run_id: &str,
    session: Option<&CaptureSession>,
    now: f64,
) -> Option<usize> {
    if raw.is_empty() {
        return Some(0);
    }
    let session = session?;
    if raw.len() > MAX_BYTES as usize
        || raw.len() as i64 > session.max_bytes
        || !raw.ends_with(b"\n")
    {
        return None;
    }
    let lines = split_lines(raw);
    let limit = MAX_RECORDS.min(session.max_records) as usize;
    if lines.is_empty() || lines.len() > limit {
        return None;
    }
    for line in &lines {
        let row = json::parse_object(line)?;
        match validated_record(&row, Some(run_id), Some(session), now)? {
            Validated { key: None, tag } if !matches!(tag.as_str(), "missing" | "unsupported") => {
                return None
            }
            _ => {}
        }
    }
    Some(lines.len())
}

/// `bytes.splitlines()`: only `\n`, `\r` and `\r\n` end a line.
fn split_lines(raw: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index < raw.len() {
        if matches!(raw[index], b'\n' | b'\r') {
            lines.push(&raw[start..index]);
            if raw[index] == b'\r' && raw.get(index + 1) == Some(&b'\n') {
                index += 1;
            }
            start = index + 1;
        }
        index += 1;
    }
    if start < raw.len() {
        lines.push(&raw[start..]);
    }
    lines
}

struct Group {
    key: [String; 4],
    bridge: Vec<Json>,
    native: Vec<Json>,
}

fn issue(status: &str, reason: &str) -> Json {
    Json::object(vec![
        ("status", Json::Str(status.to_owned())),
        ("reason", Json::Str(reason.to_owned())),
    ])
}

fn identity(key: &[String; 4]) -> Json {
    Json::Arr(key.iter().map(|part| Json::Str(part.clone())).collect())
}

fn join_entry(status: &str, reason: Option<&str>, scope: Option<&str>, key: &[String; 4]) -> Json {
    let mut entries = vec![("status", Json::Str(status.to_owned()))];
    if let Some(reason) = reason {
        entries.push(("reason", Json::Str(reason.to_owned())));
    }
    if let Some(scope) = scope {
        entries.push(("scope", Json::Str(scope.to_owned())));
    }
    entries.push(("identity", identity(key)));
    Json::object(entries)
}

fn status_of(entry: &Json) -> &str {
    entry.get("status").and_then(Json::as_str).unwrap_or("")
}

/// Join ingress and native rows using exact identity and keyed continuity.
pub(crate) fn join_binding_records(
    records: &[Json],
    session: Option<&CaptureSession>,
    now: f64,
) -> Json {
    let aggregate_limit = session.map_or(MAX_BYTES, |s| MAX_BYTES.min(s.max_bytes)) as usize;
    let record_limit = session.map_or(MAX_RECORDS, |s| MAX_RECORDS.min(s.max_records)) as usize;
    let mut groups: Vec<Group> = Vec::new();
    let mut issues: Vec<Json> = Vec::new();
    let mut aggregate_bytes = 0usize;
    let mut aggregate_exceeded = false;
    let mut record_limit_exceeded = false;
    for (index, record) in records.iter().enumerate() {
        if index + 1 > record_limit {
            issues.push(issue("ambiguous", "record_limit_exceeded"));
            record_limit_exceeded = true;
            break;
        }
        if !matches!(record, Json::Obj(_)) {
            issues.push(issue("invalid", "record_not_object"));
            continue;
        }
        let encoded_size = json::canonical(record).map(|bytes| bytes.len() + 1);
        let Some(size) = encoded_size
            .filter(|size| *size <= aggregate_limit && aggregate_bytes + *size <= aggregate_limit)
        else {
            issues.clear();
            issues.push(issue("invalid", "record_size"));
            aggregate_exceeded = true;
            break;
        };
        aggregate_bytes += size;
        let Some(normalized) = validated_record(record, None, session, now) else {
            issues.push(issue("invalid", "record_shape"));
            continue;
        };
        let Some(key) = normalized.key else {
            let event = canonical_event_name(
                record
                    .get("event_name")
                    .and_then(Json::as_str)
                    .unwrap_or(""),
            );
            if !BINDABLE_CODEX_HOOK_EVENTS.contains(&event.as_str()) {
                issues.push(issue("not_applicable", "native_receipt_unsupported_event"));
            } else {
                let reason = match normalized.tag.as_str() {
                    "missing" => "missing_tool_use_id",
                    "unsupported" => "unsupported_tool_use_id",
                    other => other,
                };
                issues.push(issue("unbound", reason));
            }
            continue;
        };
        let position = groups.iter().position(|group| group.key == key);
        let group = match position {
            Some(position) => &mut groups[position],
            None => {
                groups.push(Group {
                    key,
                    bridge: Vec::new(),
                    native: Vec::new(),
                });
                groups.last_mut().expect("group just pushed")
            }
        };
        if normalized.tag == "bridge_ingress" {
            group.bridge.push(record.clone());
        } else {
            group.native.push(record.clone());
        }
    }
    if aggregate_exceeded || record_limit_exceeded {
        groups.clear();
    }
    let joins: Vec<Json> = groups.iter().map(join_group).collect();
    let statuses: Vec<&str> = joins
        .iter()
        .chain(issues.iter())
        .map(status_of)
        .filter(|status| *status != "not_applicable")
        .collect();
    let status = if statuses.contains(&"invalid") {
        "invalid"
    } else if statuses.contains(&"ambiguous") {
        "ambiguous"
    } else if statuses.is_empty() {
        if joins.is_empty() && issues.is_empty() {
            "unbound"
        } else {
            "not_applicable"
        }
    } else if statuses.contains(&"unbound") {
        "unbound"
    } else {
        "bound"
    };
    Json::object(vec![
        ("schema", Json::Str(CAPTURE_SCHEMA.to_owned())),
        (
            "fingerprint_scheme",
            Json::Str(FINGERPRINT_SCHEME.to_owned()),
        ),
        ("scope", Json::Str("native_edge_binding".to_owned())),
        ("status", Json::Str(status.to_owned())),
        ("joins", Json::Arr(joins)),
        ("issues", Json::Arr(issues)),
    ])
}

fn join_group(group: &Group) -> Json {
    let key = &group.key;
    if !BINDABLE_CODEX_HOOK_EVENTS.contains(&key[2].as_str()) {
        return join_entry(
            "not_applicable",
            Some("native_receipt_unsupported_event"),
            None,
            key,
        );
    }
    if group.bridge.len() > 1 || group.native.len() > 1 {
        return join_entry("ambiguous", Some("duplicate_join_rows"), None, key);
    }
    let (Some(bridge), Some(native)) = (group.bridge.first(), group.native.first()) else {
        return join_entry("unbound", Some("missing_join_side"), None, key);
    };
    if bridge.get("forwarded_payload_hmac_sha256") != native.get("forwarded_payload_hmac_sha256") {
        return join_entry("invalid", Some("payload_fingerprint_mismatch"), None, key);
    }
    join_entry("bound", None, Some("native_edge_binding"), key)
}
