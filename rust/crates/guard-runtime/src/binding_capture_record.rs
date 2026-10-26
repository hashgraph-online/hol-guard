//! Row identity rules shared by the capture writer and the local join.

use crate::binding_capture_crypto::{
    is_lower_hex, valid_run_id, whole_seconds, CaptureSession, CAPTURE_SCHEMA, FINGERPRINT_SCHEME,
};
use crate::binding_capture_json as json;
use crate::binding_capture_json::Json;
use crate::binding_capture_receipt::receipt_projection;

/// Mirrors `MANAGED_CODEX_HOOK_EVENTS` in the Python hook manifest.
pub(crate) const MANAGED_CODEX_HOOK_EVENTS: [&str; 4] = [
    "PreToolUse",
    "PermissionRequest",
    "UserPromptSubmit",
    "PostToolUse",
];
pub(crate) const BINDABLE_CODEX_HOOK_EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];

/// `runtime_hook_event_name({"hook_event_name": raw})` for printable ASCII.
pub(crate) fn canonical_event_name(raw: &str) -> String {
    let compact = raw.to_ascii_lowercase().replace(['_', '-'], "");
    match compact.as_str() {
        "pretool"
        | "pretooluse"
        | "pretoolcall"
        | "beforeshellexecution"
        | "beforereadfile"
        | "beforewritefile"
        | "beforemcpexecution" => "PreToolUse",
        "posttool"
        | "posttooluse"
        | "posttoolcall"
        | "aftershellexecution"
        | "afterreadfile"
        | "afterwritefile"
        | "aftermcpexecution" => "PostToolUse",
        "permissionrequest" | "permissionrequestv2" => "PermissionRequest",
        "prompt" | "userpromptsubmit" | "userpromptsubmitted" => "UserPromptSubmit",
        _ => return raw.to_owned(),
    }
    .to_owned()
}

pub(crate) fn bounded_text(value: &str, maximum: usize) -> Option<&str> {
    (!value.is_empty()
        && value.chars().count() <= maximum
        && value.chars().all(|c| ('\u{21}'..='\u{7e}').contains(&c)))
    .then_some(value)
}

pub(crate) enum ToolUseId {
    Missing,
    Invalid,
    Present(String),
}

pub(crate) fn tool_use_id(payload: &Json) -> ToolUseId {
    match payload.get("tool_use_id") {
        None => ToolUseId::Missing,
        Some(Json::Str(text))
            if (1..=256).contains(&text.len())
                && text
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') =>
        {
            ToolUseId::Present(text.clone())
        }
        Some(_) => ToolUseId::Invalid,
    }
}

/// Identity fields every captured row starts from (`_base_row`).
pub(crate) fn base_row(
    session: &CaptureSession,
    route: &str,
    harness: &str,
    event_name: &str,
    payload: &Json,
) -> Option<Vec<(String, Json)>> {
    let harness = bounded_text(harness, 64)?;
    let event = canonical_event_name(bounded_text(event_name, 64)?);
    if !MANAGED_CODEX_HOOK_EVENTS.contains(&event.as_str()) {
        return None;
    }
    let (state, identifier) = match tool_use_id(payload) {
        ToolUseId::Missing => ("missing", None),
        ToolUseId::Invalid => ("unsupported", None),
        ToolUseId::Present(id) => ("present", Some(id)),
    };
    let text = |value: &str| Json::Str(value.to_owned());
    let mut row = vec![
        ("schema".to_owned(), text(CAPTURE_SCHEMA)),
        ("fingerprint_scheme".to_owned(), text(FINGERPRINT_SCHEME)),
        ("key_id".to_owned(), text(&session.key_id)),
        ("run_id".to_owned(), text(&session.run_id)),
        ("route".to_owned(), text(route)),
        ("harness".to_owned(), text(harness)),
        ("event_name".to_owned(), text(&event)),
        ("tool_use_id_state".to_owned(), text(state)),
    ];
    if let Some(id) = identifier {
        row.push(("tool_use_id".to_owned(), Json::Str(id)));
    }
    Some(row)
}

/// Exact join identity (run, harness, event, tool use id) or a bounded reason.
pub(crate) struct Validated {
    pub(crate) key: Option<[String; 4]>,
    pub(crate) tag: String,
}

fn reason(tag: &str) -> Option<Validated> {
    Some(Validated {
        key: None,
        tag: tag.to_owned(),
    })
}

fn text<'a>(value: &'a Json, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Json::as_str)
}

pub(crate) fn validated_record(
    value: &Json,
    run_id: Option<&str>,
    session: Option<&CaptureSession>,
    now: f64,
) -> Option<Validated> {
    if text(value, "schema") != Some(CAPTURE_SCHEMA) {
        return None;
    }
    let row_run_id = text(value, "run_id")?;
    let harness = text(value, "harness")?;
    let event_name = text(value, "event_name")?;
    let route = text(value, "route")?;
    let state = text(value, "tool_use_id_state")?;
    if !valid_run_id(row_run_id)
        || run_id.is_some_and(|expected| expected != row_run_id)
        || bounded_text(harness, 64).is_none()
        || harness != "codex"
        || bounded_text(event_name, 64).is_none()
        || !MANAGED_CODEX_HOOK_EVENTS.contains(&canonical_event_name(event_name).as_str())
        || !matches!(route, "bridge_ingress" | "native_worker")
        || !matches!(state, "missing" | "unsupported" | "present")
        || text(value, "fingerprint_scheme") != Some(FINGERPRINT_SCHEME)
        || !text(value, "key_id").is_some_and(|id| is_lower_hex(id, 32))
        || !text(value, "row_mac").is_some_and(|mac| is_lower_hex(mac, 64))
    {
        return None;
    }
    let canonical_event = canonical_event_name(event_name);
    let mut expected = vec![
        "schema",
        "fingerprint_scheme",
        "key_id",
        "run_id",
        "route",
        "harness",
        "event_name",
        "tool_use_id_state",
        "row_mac",
        "forwarded_payload_hmac_sha256",
    ];
    if state == "present" {
        expected.push("tool_use_id");
    }
    if route == "bridge_ingress" {
        expected.push("raw_payload_hmac_sha256");
    } else {
        expected.extend(["decision_scope", "sealed_receipt"]);
    }
    let mut actual = value.keys();
    actual.sort_unstable();
    expected.sort_unstable();
    if actual != expected
        || !text(value, "forwarded_payload_hmac_sha256").is_some_and(|mac| is_lower_hex(mac, 64))
        || (route == "bridge_ingress"
            && !text(value, "raw_payload_hmac_sha256").is_some_and(|mac| is_lower_hex(mac, 64)))
        || (route == "native_worker" && text(value, "decision_scope") != Some("native_edge"))
    {
        return None;
    }
    let Some(session) = session else {
        return reason("missing_capture_key");
    };
    if session.run_id != row_run_id || Some(session.key_id.as_str()) != text(value, "key_id") {
        return reason("capture_key_mismatch");
    }
    if session.expires_at <= whole_seconds(now) {
        return reason("capture_key_expired");
    }
    if !session.verify_row_hmac(value, now) {
        return reason("row_mac_mismatch");
    }
    if route == "native_worker" {
        let opened = crate::binding_capture_crypto::open_receipt(
            session,
            value,
            value.get("sealed_receipt")?,
            now,
        )?;
        let projection = receipt_projection(&opened)?;
        if json::encode(&projection) != json::encode(&opened)
            || text(&opened, "harness") != Some(harness)
            || text(&opened, "event_name") != Some(canonical_event.as_str())
        {
            return None;
        }
    }
    if matches!(state, "missing" | "unsupported") {
        return if value.get("tool_use_id").is_none() {
            reason(state)
        } else {
            None
        };
    }
    let identifier = text(value, "tool_use_id")?;
    let probe = Json::object(vec![("tool_use_id", Json::Str(identifier.to_owned()))]);
    match tool_use_id(&probe) {
        ToolUseId::Present(valid) if valid == identifier => Some(Validated {
            key: Some([
                row_run_id.to_owned(),
                harness.to_owned(),
                canonical_event,
                identifier.to_owned(),
            ]),
            tag: route.to_owned(),
        }),
        _ => None,
    }
}
