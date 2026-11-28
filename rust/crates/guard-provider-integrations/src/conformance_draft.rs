//! A first `recordings.json` for a provider manifest, behind `hol-guard extensions generate
//! --provider` (BP-T180).
//!
//! The conformance kit wants, for every capability, a recorded response for each verdict the
//! manifest maps plus `unknown`, and one for each required failure. A contributor should not write
//! that first set by hand, so this drafts it from the manifest alone:
//!
//! - one `200` answer per entry of the verdict table, with the provider's own verdict string at the
//!   verdict pointer, the first declared reason code on a non-`ok` answer and the minimum lifetime;
//! - one `200` answer with a verdict string the table does not list, which reads `unknown`;
//! - `401`, `429` and `503` answers, a body one byte over `maxResponseBytes` and a body that is not
//!   JSON.
//!
//! Each expectation is what the resident makes of the drafted body, read through the same code the
//! kit runs, and the whole draft is checked by the kit's `recordings` check before it is returned.
//! The bodies are placeholders shaped by the manifest's pointers. The contributor replaces them with
//! real recorded responses before the pull request; nothing here calls a provider.

use guard_command::provider_integration_compile::{
    compile_provider_integration, CompiledProviderCapabilityV1,
};
use guard_contracts::ProviderVerdictV1;
use serde_json::{json, Map, Value};

use crate::conformance::{check_recordings, recorded_outcome, RecordedFailure};
use crate::conformance_fixtures::{
    parse_recordings, MAX_PAD_BYTES, MAX_RECORDINGS, RECORDINGS_SCHEMA,
};

/// A drafted recordings file: the exact text to write and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DraftedRecordings {
    pub provider_id: String,
    pub text: String,
    pub count: usize,
}

/// Why no draft was produced. Each variant has a stable [`code`](Self::code).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftError {
    /// The manifest does not compile; carries the compiler's code.
    Compile(&'static str),
    /// The manifest maps more verdicts than one recordings file may hold.
    TooMany,
    /// A drafted body does not read as intended; carries the kit's problems.
    Unsettled(Vec<String>),
}

impl DraftError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Compile(code) => code,
            Self::TooMany => "recordings_too_many",
            Self::Unsettled(_) => "recordings_draft_unsettled",
        }
    }
}

struct Entry {
    name: String,
    capability: &'static str,
    status: u16,
    body: String,
    pad: Option<u64>,
    expect: Value,
}

/// Draft the recordings for `manifest`.
pub fn draft_recordings(manifest: &[u8]) -> Result<DraftedRecordings, DraftError> {
    let compiled = compile_provider_integration(manifest, &[])
        .map_err(|error| DraftError::Compile(error.code()))?;
    let max = compiled.limits.max_response_bytes;
    let mut entries = Vec::new();
    for capability in &compiled.capabilities {
        draft_capability(capability, max, &mut entries)?;
    }
    if entries.len() > MAX_RECORDINGS {
        return Err(DraftError::TooMany);
    }
    let recordings: Vec<Value> = entries.into_iter().map(entry_value).collect();
    let mut text = serde_json::to_string_pretty(&json!({
        "schema": RECORDINGS_SCHEMA,
        "recordings": recordings,
    }))
    .unwrap_or_default();
    text.push('\n');
    let parsed = parse_recordings(text.as_bytes())
        .map_err(|error| DraftError::Unsettled(vec![error.code()]))?;
    let borrowed: Vec<_> = parsed.iter().map(|recording| recording.borrow()).collect();
    let check = check_recordings(&compiled, &borrowed);
    if !check.passed() {
        return Err(DraftError::Unsettled(check.problems));
    }
    Ok(DraftedRecordings {
        provider_id: compiled.id.clone(),
        count: parsed.len(),
        text,
    })
}

fn draft_capability(
    capability: &CompiledProviderCapabilityV1,
    max_response_bytes: u64,
    entries: &mut Vec<Entry>,
) -> Result<(), DraftError> {
    let id = capability.capability.as_str();
    let stem = id.replace('.', "-");
    let mut index = 0usize;
    for (source, verdict) in &capability.verdict_map {
        index += 1;
        let body = answer_body(capability, source, *verdict);
        let name = format!("{stem}-{}-{index}", verdict_word(*verdict));
        entries.push(signal_entry(
            capability,
            max_response_bytes,
            name,
            id,
            body,
        )?);
    }
    let unmapped = unmapped_verdict(capability);
    let body = answer_body(capability, &unmapped, ProviderVerdictV1::Unknown);
    entries.push(signal_entry(
        capability,
        max_response_bytes,
        format!("{stem}-unmapped"),
        id,
        body,
    )?);
    let failures = [
        (
            "key-refused",
            401,
            "{}".to_owned(),
            None,
            RecordedFailure::Unauthorized,
        ),
        (
            "rate-limited",
            429,
            "{}".to_owned(),
            None,
            RecordedFailure::RateLimited,
        ),
        (
            "server-error",
            503,
            "{}".to_owned(),
            None,
            RecordedFailure::Status,
        ),
        (
            "oversize",
            200,
            "{}".to_owned(),
            Some(max_response_bytes.saturating_add(1)),
            RecordedFailure::Oversize,
        ),
        (
            "malformed",
            200,
            // One byte, so it stays under every `maxResponseBytes` and reads as malformed, not oversize.
            "{".to_owned(),
            None,
            RecordedFailure::Malformed,
        ),
    ];
    for (suffix, status, body, pad, failure) in failures {
        if pad.is_some_and(|pad| pad > MAX_PAD_BYTES as u64) {
            return Err(DraftError::Unsettled(vec![format!(
                "{id}: maxResponseBytes is larger than a recording may pad"
            )]));
        }
        entries.push(Entry {
            name: format!("{stem}-{suffix}"),
            capability: id,
            status,
            body,
            pad,
            expect: json!({"failure": failure.code()}),
        });
    }
    Ok(())
}

/// A `200` entry whose expectation is what the resident reads from `body`.
fn signal_entry(
    capability: &CompiledProviderCapabilityV1,
    max_response_bytes: u64,
    name: String,
    id: &'static str,
    body: String,
) -> Result<Entry, DraftError> {
    let answer = recorded_outcome(capability, max_response_bytes, 200, body.as_bytes()).map_err(
        |failure| {
            DraftError::Unsettled(vec![format!(
                "{name}: the drafted body reads as {}",
                failure.code()
            )])
        },
    )?;
    Ok(Entry {
        name,
        capability: id,
        status: 200,
        body,
        pad: None,
        expect: json!({
            "verdict": verdict_word(answer.verdict),
            "reasonCodes": answer.reason_codes,
        }),
    })
}

fn entry_value(entry: Entry) -> Value {
    let mut object = Map::new();
    object.insert("name".to_owned(), Value::String(entry.name));
    object.insert(
        "capability".to_owned(),
        Value::String(entry.capability.to_owned()),
    );
    object.insert("status".to_owned(), json!(entry.status));
    object.insert("body".to_owned(), Value::String(entry.body));
    if let Some(pad) = entry.pad {
        object.insert("padToBytes".to_owned(), json!(pad));
    }
    object.insert("expect".to_owned(), entry.expect);
    Value::Object(object)
}

/// A body with `source` at the verdict pointer, plus a reason code and lifetime where the manifest
/// reads them and their pointers do not collide with the verdict's.
fn answer_body(
    capability: &CompiledProviderCapabilityV1,
    source: &str,
    verdict: ProviderVerdictV1,
) -> String {
    let mut document = Value::Object(Map::new());
    insert_at(
        &mut document,
        &capability.verdict_pointer,
        Value::String(source.to_owned()),
    );
    if let Some(codes) = &capability.reason_codes {
        let first = codes
            .allow
            .first()
            .filter(|_| !matches!(verdict, ProviderVerdictV1::Ok | ProviderVerdictV1::Unknown));
        if let Some(code) = first {
            insert_at(&mut document, &codes.pointer, json!([code]));
        }
    }
    if let Some(ttl) = &capability.ttl {
        insert_at(&mut document, &ttl.pointer, json!(ttl.min_seconds));
    }
    serde_json::to_string(&document).unwrap_or_default()
}

/// Set `value` at a JSON pointer, creating objects on the way. A pointer that runs through a value
/// already set, or names one already set, is left alone, so the verdict always wins. The empty
/// pointer names the whole document, which only an untouched document gives up.
fn insert_at(document: &mut Value, pointer: &str, value: Value) {
    if pointer.is_empty() {
        if document.as_object().is_some_and(Map::is_empty) {
            *document = value;
        }
        return;
    }
    let Some(rest) = pointer.strip_prefix('/') else {
        return;
    };
    let segments: Vec<String> = rest
        .split('/')
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect();
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut current = document;
    for segment in parents {
        let Value::Object(object) = current else {
            return;
        };
        current = object
            .entry(segment.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if let Value::Object(object) = current {
        object.entry(last.clone()).or_insert(value);
    }
}

/// A verdict string the table does not list.
fn unmapped_verdict(capability: &CompiledProviderCapabilityV1) -> String {
    let mut candidate = "unlisted".to_owned();
    let mut index = 0u32;
    while capability.verdict_map.contains_key(&candidate) {
        index += 1;
        candidate = format!("unlisted-{index}");
    }
    candidate
}

fn verdict_word(verdict: ProviderVerdictV1) -> &'static str {
    match verdict {
        ProviderVerdictV1::Ok => "ok",
        ProviderVerdictV1::Caution => "caution",
        ProviderVerdictV1::Danger => "danger",
        ProviderVerdictV1::Unknown => "unknown",
    }
}

#[cfg(test)]
#[path = "conformance_draft_tests.rs"]
mod tests;
