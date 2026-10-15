//! The transition diagnostic of Python's `_write_transition_observation`.
//! A daemon answer to a hook that carries a transition probe may name a
//! `guard_transition_observation`; the bridge writes it to stderr only when
//! it is exactly what `transition_hook_observation` builds from the probe in
//! the hook input and the Rust decision receipt it carries. The diagnostic
//! never changes the answer, approves anything, or enables a fallback.

use std::io::{self, Write};

use crate::pyjson::{self, PyVal};

use self::receipt::dumps_sorted;

const PROBE_FIELD: &str = "guard_transition_probe";
const PROBE_SCHEMA: &str = "hol-guard.transition-hook-probe.v1";
const OBSERVATION_SCHEMA: &str = "hol-guard.transition-hook-observation.v1";
const REQUEST_PREFIX: &str = "transition-hook-";

/// `str(uuid.UUID(text)) == text`: the canonical lowercase hyphenated form.
fn canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => matches!(byte, b'0'..=b'9' | b'a'..=b'f'),
        })
}

/// `transition-hook-[0-9a-f]{32}`.
fn probe_request(text: &str) -> bool {
    text.strip_prefix(REQUEST_PREFIX).is_some_and(|rest| {
        rest.len() == 32 && rest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// `transition_hook_probe(payload)`: the probe's operation and request ids.
fn probe(payload: &PyVal) -> Option<(&str, &str)> {
    let probe = payload.get(PROBE_FIELD)?;
    let entries = probe.as_dict()?;
    let keys = ["schema", "operation_id", "request_id"];
    if entries.len() != keys.len() || !entries.iter().all(|(key, _)| keys.contains(&key.as_str())) {
        return None;
    }
    let operation = probe.get("operation_id")?.as_str()?;
    let request = probe.get("request_id")?.as_str()?;
    let valid = probe.get("schema")?.as_str() == Some(PROBE_SCHEMA)
        && probe_request(request)
        && canonical_uuid(operation);
    valid.then_some((operation, request))
}

/// The stderr line for `envelope`, the answer's
/// `guard_transition_observation`, given the hook input; `None` when Python
/// writes nothing.
pub(super) fn observation_line(hook_input: &str, envelope: &PyVal) -> Option<String> {
    let entries = envelope.as_dict()?;
    let payload = pyjson::parse_mapping_lone_surrogates(hook_input)
        .ok()?
        .value;
    payload.as_dict()?;
    let (operation, request) = probe(&payload)?;
    let native = envelope.get("native_receipt")?;
    if !receipt::valid(native) {
        return None;
    }
    let text = |name: &str| native.get(name).and_then(PyVal::as_str);
    let observable = text("request_id") == Some(request)
        && text("event_name") == Some("PreToolUse")
        && matches!(text("harness"), Some("codex" | "omp"))
        && text("payload_kind") == Some("inline")
        && native.get("observe_mode") == Some(&PyVal::Bool(false));
    // `envelope != validated`: exactly the observation built from the
    // probe and the receipt it carries.
    let keys = ["schema", "operation_id", "request_id", "native_receipt"];
    let exact = entries.len() == keys.len()
        && entries.iter().all(|(key, _)| keys.contains(&key.as_str()))
        && envelope.get("schema").and_then(PyVal::as_str) == Some(OBSERVATION_SCHEMA)
        && envelope.get("operation_id").and_then(PyVal::as_str) == Some(operation)
        && envelope.get("request_id").and_then(PyVal::as_str) == Some(request);
    (observable && exact).then(|| dumps_sorted(envelope, true) + "\n")
}

/// Write the diagnostic, if any; a failed write never interferes with the
/// enforcement answer.
pub(super) fn write(hook_input: &str, envelope: &PyVal) {
    if let Some(line) = observation_line(hook_input, envelope) {
        let mut stderr = io::stderr().lock();
        let _ = stderr
            .write_all(line.as_bytes())
            .and_then(|()| stderr.flush());
    }
}

#[path = "codex_hook_bridge_observation_receipt.rs"]
mod receipt;

#[cfg(all(test, unix))]
#[path = "codex_hook_bridge_observation_tests.rs"]
mod tests;
