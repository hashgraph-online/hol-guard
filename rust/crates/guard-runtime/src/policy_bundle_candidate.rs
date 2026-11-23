//! `bundle_candidate` policy-document query: the decisions a verified policy
//! bundle activates on this device, or the code it is refused with. Ported
//! from `policy_bundle_candidate_decisions` (`runner.py`), which used to make
//! four resident round trips for one answer: the canonical compile, the
//! shadow choice, the legacy materialization and the shadow verdict.
//!
//! `{"bundle", "is_v2", "device_id", "device_name", "canonical_enforcement",
//! "stored_legacy", "existing", "offset"?}` answers `{"decisions",
//! "rejection", "rule_id", "mismatch", "total", "next"}`. `decisions` are
//! persisted-decision field maps, one page of them: a page holds at most
//! `PAGE_BYTES` of serialized rows, `total` counts every row and `next` is
//! the offset of the following page, or `null` on the last one. Python asks
//! again from `next`, so no single answer outgrows the result wire.
//! `rejection` is `null` when the candidate may be activated. `rule_id` names
//! the rule a canonical compile failure came from. `mismatch` is the
//! `policy_bundle/shadow_mismatch` event payload Python records, or `null`.
//! The answer always travels as `ok`: a refused bundle is a verdict, so the
//! daemon route still answers the request.

use std::time::Instant;

use serde_json::{json, Map, Value};

/// The query name Python sends through `policy_query`.
pub(super) const QUERY: &str = "bundle_candidate";

const CANONICAL_CONTRACT: &str = "guard-policy-bundle.v2";
const CANONICAL_SOURCE: &str = "policy-bundle-canonical";
/// `CANONICAL_COMPILE_REJECTION_PREFIX` (`policy_bundle_parser.py`).
const COMPILE_PREFIX: &str = "canonical_compile_";
/// `NATIVE_UNAVAILABLE_REJECTION`: an outage never reads as a verdict.
const UNAVAILABLE: &str = "native_policy_bundle_unavailable";
const SHADOW_UNAVAILABLE: &str = "native_shadow_unavailable";
const FIELDS: [&str; 8] = [
    "bundle",
    "is_v2",
    "device_id",
    "device_name",
    "canonical_enforcement",
    "stored_legacy",
    "existing",
    "offset",
];
/// Serialized decision bytes one answer page carries; a single larger row
/// still travels alone.
const PAGE_BYTES: usize = 8 * 1024 * 1024;
/// `PolicyDecision`'s fields; a compiled row naming any other is malformed.
const DECISION_FIELDS: [&str; 11] = [
    "harness",
    "scope",
    "action",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "reason",
    "owner",
    "source",
    "expires_at",
];
/// `_SHADOW_KEYS` (`runner_policy_shadow.py`): what the shadow compares.
const SHADOW_KEYS: [&str; 8] = [
    "harness",
    "scope",
    "artifact_id",
    "artifact_hash",
    "workspace",
    "publisher",
    "action",
    "expires_at",
];
const SCOPES: [&str; 5] = ["artifact", "workspace", "publisher", "harness", "global"];
const BUNDLE_ACTIONS: [&str; 3] = ["allow", "block", "review"];
const MAX_COMPILED_ROWS: usize = 10_000;

/// Why no decisions could be built: the rejection code and, for a canonical
/// compile failure, the rule it came from.
type Refusal = (String, Option<String>);

/// Answers the query in the envelope the other policy-document queries use:
/// `{"ok": ...}`, or a `ValueError` for a request it cannot read.
pub(super) fn query(input: &Value, deadline: Instant) -> Value {
    let answer = input
        .as_object()
        .filter(|fields| fields.keys().all(|key| FIELDS.contains(&key.as_str())))
        .and_then(Request::read)
        .and_then(|request| request.answer(deadline));
    match answer {
        Some(answer) => json!({"ok": answer}),
        None => json!({"error": {
            "type": "ValueError",
            "message": "policy_document_bundle_candidate_invalid",
        }}),
    }
}

struct Request<'a> {
    bundle: &'a Map<String, Value>,
    is_v2: bool,
    device_id: &'a str,
    device_name: &'a str,
    canonical_enforcement: bool,
    stored_legacy: &'a Value,
    existing: &'a Value,
    offset: usize,
}

impl<'a> Request<'a> {
    fn read(fields: &'a Map<String, Value>) -> Option<Self> {
        let text = |key: &str| fields.get(key).and_then(Value::as_str);
        let flag = |key: &str| fields.get(key).and_then(Value::as_bool);
        Some(Self {
            bundle: fields.get("bundle")?.as_object()?,
            is_v2: flag("is_v2")?,
            device_id: text("device_id")?,
            device_name: text("device_name")?,
            canonical_enforcement: flag("canonical_enforcement")?,
            stored_legacy: fields.get("stored_legacy").unwrap_or(&Value::Null),
            existing: fields.get("existing").unwrap_or(&Value::Null),
            offset: match fields.get("offset") {
                None => 0,
                Some(offset) => usize::try_from(offset.as_u64()?).ok()?,
            },
        })
    }

    /// One page of the verdict, or `None` for an offset past the last row.
    fn answer(&self, deadline: Instant) -> Option<Value> {
        let (decisions, rejection, rule_id, mismatch) = match self.decide(deadline) {
            Ok((decisions, rejection, mismatch)) => (decisions, rejection, None, mismatch),
            Err((code, rule_id)) => (Vec::new(), Some(code), rule_id, Value::Null),
        };
        let (page, next) = page(&decisions, self.offset)?;
        Some(json!({
            "decisions": page,
            "rejection": rejection,
            "rule_id": rule_id,
            "mismatch": mismatch,
            "total": decisions.len(),
            "next": next,
        }))
    }

    fn decide(&self, deadline: Instant) -> Result<(Vec<Value>, Option<String>, Value), Refusal> {
        if !self.is_v2 {
            return Ok((self.rows(self.bundle, deadline)?, None, Value::Null));
        }
        let canonical = canonical_rows(self.bundle, self.device_id, self.device_name, deadline)?;
        let shadow = crate::policy_shadow_source::dispatch(&json!({
            "candidate": self.bundle,
            "stored_legacy": object_or_null(self.stored_legacy),
            "existing": object_or_null(self.existing),
        }))
        .ok();
        let (source, evaluating) = shadow.as_ref().map_or((None, false), |answer| {
            (
                answer.get("legacy").and_then(Value::as_str),
                answer.get("evaluating").and_then(Value::as_bool) == Some(true),
            )
        });
        let legacy_payload = match source {
            Some("stored") => self.stored_legacy.as_object(),
            Some("existing") => self.existing.as_object(),
            _ => None,
        };
        let legacy = match legacy_payload {
            Some(payload) => self.shadow_rows(payload, deadline)?,
            None => Vec::new(),
        };
        let (reasons, rejection) = match shadow {
            None => (
                vec![json!(SHADOW_UNAVAILABLE)],
                Some(SHADOW_UNAVAILABLE.to_owned()),
            ),
            // An Evaluate bundle keeps its canonical rows empty on purpose,
            // so it has nothing to drift from.
            Some(_) if evaluating => (Vec::new(), None),
            Some(_) => self.verdict(&legacy, &canonical),
        };
        let mismatch = if reasons.is_empty() {
            Value::Null
        } else {
            json!({
                "canonicalRows": canonical.len(),
                "legacyRows": legacy.len(),
                "reasonCodes": reasons,
                "status": "mismatch",
            })
        };
        Ok((canonical, rejection, mismatch))
    }

    /// `_build_policy_bundle_decisions`: a v2 bundle compiles canonically,
    /// any other is materialized by the policy-bundle authority.
    fn rows(&self, bundle: &Map<String, Value>, deadline: Instant) -> Result<Vec<Value>, Refusal> {
        if bundle.get("contractVersion").and_then(Value::as_str) == Some(CANONICAL_CONTRACT) {
            return canonical_rows(bundle, self.device_id, self.device_name, deadline);
        }
        materialized_rows(bundle, self.device_id, self.device_name, deadline)
            .map_err(|code| (code, None))
    }

    /// The shadow's rows. A shadow that no longer compiles cannot show
    /// agreement, so it stands in as unavailable rather than refusing a
    /// candidate that is itself well formed; an authority refusal still
    /// refuses the candidate.
    fn shadow_rows(
        &self,
        bundle: &Map<String, Value>,
        deadline: Instant,
    ) -> Result<Vec<Value>, Refusal> {
        match self.rows(bundle, deadline) {
            Err((code, _)) if code.starts_with(COMPILE_PREFIX) => Ok(Vec::new()),
            other => other,
        }
    }

    fn verdict(&self, legacy: &[Value], canonical: &[Value]) -> (Vec<Value>, Option<String>) {
        let answer = crate::policy_shadow_verdict::dispatch(&json!({
            "legacy": shadow_projection(legacy),
            "canonical": shadow_projection(canonical),
            "evaluating": false,
            "canonical_enforcement": self.canonical_enforcement,
        }));
        let reasons = answer
            .as_ref()
            .ok()
            .and_then(|answer| answer.get("reason_codes"))
            .and_then(Value::as_array)
            .cloned();
        match (
            reasons,
            answer.as_ref().ok().map(|answer| &answer["rejection"]),
        ) {
            (Some(reasons), Some(Value::String(code))) => (reasons, Some(code.clone())),
            (Some(reasons), Some(Value::Null)) => (reasons, None),
            // Without the verdict the candidate cannot be proven equivalent.
            _ => (
                vec![json!(SHADOW_UNAVAILABLE)],
                Some(SHADOW_UNAVAILABLE.to_owned()),
            ),
        }
    }
}

/// The rows from `offset` that fit in `PAGE_BYTES`, at least one, and the
/// offset after them when rows remain.
fn page(rows: &[Value], offset: usize) -> Option<(&[Value], Option<usize>)> {
    let rest = rows.get(offset..)?;
    let mut bytes = 0usize;
    let mut count = 0usize;
    for row in rest {
        bytes = bytes.saturating_add(row.to_string().len());
        if count > 0 && bytes > PAGE_BYTES {
            break;
        }
        count += 1;
    }
    let end = offset + count;
    Some((&rest[..count], (end < rows.len()).then_some(end)))
}

fn object_or_null(value: &Value) -> Value {
    if value.is_object() {
        value.clone()
    } else {
        Value::Null
    }
}

fn shadow_projection(rows: &[Value]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let fields: Map<String, Value> = SHADOW_KEYS
                .iter()
                .map(|key| {
                    (
                        (*key).to_owned(),
                        row.get(*key).cloned().unwrap_or(Value::Null),
                    )
                })
                .collect();
            Value::Object(fields)
        })
        .collect()
}

/// `_build_canonical_policy_bundle_decisions`: the compiled rules this
/// device is in scope for, owned by their rule and saved as canonical.
fn canonical_rows(
    bundle: &Map<String, Value>,
    device_id: &str,
    device_name: &str,
    deadline: Instant,
) -> Result<Vec<Value>, Refusal> {
    let input = json!({"bundle": bundle, "device_id": device_id, "device_name": device_name});
    let unavailable = || (UNAVAILABLE.to_owned(), None);
    let answer = guard_command::policy_document::evaluate("compile_bundle", &input, deadline)
        .map_err(|_| unavailable())?;
    if let Some(error) = answer.get("error") {
        return Err(compile_refusal(error).unwrap_or_else(unavailable));
    }
    let rows = answer
        .get("ok")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() <= MAX_COMPILED_ROWS)
        .ok_or_else(unavailable)?;
    rows.iter()
        .map(|row| canonical_decision(row).ok_or_else(unavailable))
        .collect()
}

/// A `PolicyCompilationError` reports its code under the compile prefix and
/// keeps the rule it names; any other failure is no verdict at all.
fn compile_refusal(error: &Value) -> Option<Refusal> {
    if error.get("type").and_then(Value::as_str) != Some("PolicyCompilationError") {
        return None;
    }
    let code = error.get("code")?.as_str()?;
    let rule_id = error.get("rule_id")?.as_str()?;
    Some((format!("{COMPILE_PREFIX}{code}"), Some(rule_id.to_owned())))
}

/// `_compiled_rows` with the bundle actions, then the canonical owner and
/// source; a row that would not build a `PolicyDecision` is malformed.
fn canonical_decision(row: &Value) -> Option<Value> {
    let row = row.as_object()?;
    if row.len() != 3 {
        return None;
    }
    let rule_id = row.get("rule_id")?.as_str()?;
    row.get("provenance_json")?.as_str()?;
    let decision = row.get("decision")?.as_object()?;
    let member = |key: &str, set: &[&str]| {
        decision
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|value| set.contains(&value))
    };
    if !member("action", &BUNDLE_ACTIONS)
        || !member("scope", &SCOPES)
        || !decision.get("harness").is_some_and(Value::is_string)
        || decision.iter().any(|(key, value)| {
            !DECISION_FIELDS.contains(&key.as_str()) || !(value.is_string() || value.is_null())
        })
    {
        return None;
    }
    let mut fields: Map<String, Value> = DECISION_FIELDS
        .iter()
        .map(|key| {
            (
                (*key).to_owned(),
                decision.get(*key).cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    fields.insert("owner".to_owned(), json!(rule_id));
    fields.insert("source".to_owned(), json!(CANONICAL_SOURCE));
    Some(Value::Object(fields))
}

#[path = "policy_bundle_candidate_legacy.rs"]
mod legacy;
use legacy::materialized_rows;

#[cfg(test)]
#[path = "policy_bundle_candidate_tests.rs"]
mod tests;
