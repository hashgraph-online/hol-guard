//! Saved-decision read for a runtime hook evaluation.
//!
//! The resident side of the saved-decision step of the cold hook evaluation
//! (`commands_hook_native_eval.py`). For the current request hash and for the
//! legacy content hash it composes the direct, exact-command and
//! memory-pattern candidates most restrictive, with the portable Git workspace
//! (`resolve_policy_decision_lookup_with_memory_pattern`), and keeps only a
//! decision whose scope may apply to this artifact
//! (`_runtime_stored_policy_decision`). A legacy decision replaces the current
//! one only when strictly more severe. When neither matched, the Claude alias
//! of a legacy `claude-code:` artifact is probed directly. Nothing here
//! consumes a one-shot approval or writes the store.

use guard_contracts::{PolicyDecisionLookupRequestV1, RuntimeSavedLookupV1, RuntimeSavedProbeV1};
use serde_json::{json, Value};

use crate::context_digest::{python_strip, validate_context_tokens};
use crate::mcp_tool_policy_lookup::{most_restrictive, severity, without_permission_elevation};
use crate::memory_pattern::{verdict, MemoryRequest};
use crate::policy_decision_lookup_op::{
    evaluate_non_consuming, open_lookup_connection, runtime_scoped_exact_match_key,
    runtime_tool_action_portable_match_context,
};
use crate::policy_lookup_groups::remembered_rules_disabled;

const ERR_INVALID: &str = "native_policy_decision_lookup_invalid";
const IGNORED: &str = "ignored_local_integrity";
/// Saved actions a broad scope may only apply to the exact risky artifact.
const NARROWED_ACTIONS: [&str; 3] = ["allow", "warn", "review"];
const BROAD_SCOPES: [&str; 4] = ["workspace", "publisher", "harness", "global"];

/// One non-consuming store probe.
pub(crate) struct Probe<'a> {
    pub(crate) harness: &'a str,
    pub(crate) artifact_id: &'a str,
    pub(crate) artifact_hash: &'a str,
    pub(crate) workspace: Option<&'a str>,
    pub(crate) publisher: Option<&'a str>,
    pub(crate) context: Option<&'a str>,
}

pub(crate) fn evaluate(
    request: &PolicyDecisionLookupRequestV1,
    saved: &RuntimeSavedLookupV1,
) -> Result<Value, String> {
    let connection = open_lookup_connection(&request.store_path)?;
    compose(saved, |probe| {
        let mut lookup = request.clone();
        lookup.probe_groups = None;
        lookup.harness = probe.harness.to_owned();
        lookup.artifact_id = Some(probe.artifact_id.to_owned());
        lookup.artifact_hash = Some(probe.artifact_hash.to_owned());
        lookup.workspace = probe.workspace.map(str::to_owned);
        lookup.publisher = probe.publisher.map(str::to_owned);
        lookup.runtime_exact_match_context = probe.context.map(str::to_owned);
        evaluate_non_consuming(&lookup, &connection)
    })
}

/// `{lookup, decision}`: the lookup whose decision was kept (carrying the
/// integrity evidence of both hashes) and that decision, or `null`.
pub(crate) fn compose<F>(saved: &RuntimeSavedLookupV1, mut probe: F) -> Result<Value, String>
where
    F: FnMut(&Probe<'_>) -> Result<Value, String>,
{
    let current_lookup = with_memory(&saved.current, &mut probe)?;
    let mut decision = scoped(&saved.current, &current_lookup, true, &mut probe)?;
    let legacy_lookup = with_memory(&saved.legacy, &mut probe)?;
    let legacy = scoped(&saved.legacy, &legacy_lookup, true, &mut probe)?;
    let mut lookup = current_lookup;
    if !field(&legacy_lookup, IGNORED).is_null() {
        set(&mut lookup, IGNORED, field(&legacy_lookup, IGNORED).clone());
    }
    if let Some(legacy) = legacy {
        let stronger = decision
            .as_ref()
            .is_none_or(|current| severity(legacy.get("action")) > severity(current.get("action")));
        if stronger {
            let merged = field(&lookup, IGNORED).clone();
            lookup = legacy_lookup;
            if !merged.is_null() {
                set(&mut lookup, IGNORED, merged);
            }
            decision = Some(legacy);
        }
    }
    if decision.is_none() {
        if let Some(alias) = &saved.alias {
            let alias_lookup = with_memory(alias, &mut probe)?;
            decision = scoped(alias, &alias_lookup, false, &mut probe)?;
        }
    }
    Ok(json!({"lookup": lookup, "decision": decision}))
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

fn set(lookup: &mut Value, key: &str, value: Value) {
    if let Value::Object(map) = lookup {
        map.insert(key.to_owned(), value);
    }
}

/// `_optional_string`: a non-blank string, stripped.
fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(python_strip)
        .filter(|text| !text.is_empty())
}

/// The direct lookup, composed most restrictive with the exact-command and
/// memory-pattern candidates when the probe carries their inputs.
fn with_memory<F>(spec: &RuntimeSavedProbeV1, probe: &mut F) -> Result<Value, String>
where
    F: FnMut(&Probe<'_>) -> Result<Value, String>,
{
    let context = spec.exact_match_context.as_deref();
    let direct = lookup_at(spec, &spec.artifact_id, context, probe)?;
    let Some(memory) = &spec.memory else {
        return Ok(direct);
    };
    // A degraded store honors no saved decision, so the remembered-decision
    // probes cannot change the answer.
    if remembered_rules_disabled(&direct) {
        return Ok(direct);
    }
    let candidates = verdict(&MemoryRequest {
        command: memory.command.as_deref(),
        artifact_type: memory.artifact_type.as_deref(),
        artifact_id: Some(&spec.artifact_id),
        artifact_name: memory.artifact_name.as_deref(),
        harness: Some(&spec.harness),
    });
    let mut lookups = vec![direct];
    for id in candidates
        .exact_artifact_ids
        .iter()
        .chain(candidates.memory_artifact_id.iter())
    {
        lookups.push(lookup_at(spec, id, context, probe)?);
    }
    most_restrictive(&lookups).ok_or_else(|| ERR_INVALID.to_owned())
}

/// One candidate, with the portable Git-workspace authority composed in.
fn lookup_at<F>(
    spec: &RuntimeSavedProbeV1,
    artifact_id: &str,
    context: Option<&str>,
    probe: &mut F,
) -> Result<Value, String>
where
    F: FnMut(&Probe<'_>) -> Result<Value, String>,
{
    let mut at = |workspace: Option<&str>| {
        probe(&Probe {
            harness: &spec.harness,
            artifact_id,
            artifact_hash: &spec.artifact_hash,
            workspace,
            publisher: spec.publisher.as_deref(),
            context,
        })
    };
    let workspace = spec.workspace.as_deref();
    let Some(portable) = spec.portable_workspace.as_deref() else {
        return at(workspace);
    };
    let preview = without_permission_elevation(at(Some(portable))?);
    if workspace.map(python_strip) == Some(portable) {
        return Ok(preview);
    }
    let local = at(workspace)?;
    most_restrictive(&[local, preview]).ok_or_else(|| ERR_INVALID.to_owned())
}

/// `_runtime_stored_policy_decision`: the saved decision this artifact may
/// use. A missing contextual decision falls back to a context-free harness or
/// global rule; an exact v1 allow stands; and for a risky artifact a broad
/// `allow`/`warn`/`review` applies only when it names this exact artifact.
fn scoped<F>(
    spec: &RuntimeSavedProbeV1,
    lookup: &Value,
    honor_ignored: bool,
    probe: &mut F,
) -> Result<Option<Value>, String>
where
    F: FnMut(&Probe<'_>) -> Result<Value, String>,
{
    let mut decision = Some(field(lookup, "decision")).filter(|value| value.is_object());
    let fallback: Value;
    let context = spec.exact_match_context.as_deref();
    let ignored = honor_ignored && field(lookup, IGNORED).is_object();
    if decision.is_none() && context.is_some() && !ignored {
        fallback = lookup_at(spec, &spec.artifact_id, None, probe)?;
        let legacy = field(&fallback, "decision");
        if legacy.is_object() && matches!(text(legacy.get("scope")), Some("harness" | "global")) {
            decision = Some(legacy);
        }
    }
    let Some(decision) = decision else {
        return Ok(None);
    };
    let Some(action) = text(decision.get("action")) else {
        return Ok(None);
    };
    let scope = text(decision.get("scope"));
    let saved_hash = field(decision, "artifact_hash");
    let current_hash = Value::String(spec.artifact_hash.clone());
    if action == "allow" && validate_context_tokens(saved_hash, &current_hash).is_none() {
        // A valid v1 token already binds the exact request context. Broad
        // scopes are selectors only; they must not discard that exact token.
        return Ok(Some(decision.clone()));
    }
    let narrowed = NARROWED_ACTIONS.contains(&action)
        && scope.is_some_and(|scope| BROAD_SCOPES.contains(&scope))
        && spec.risk_scoped;
    if !narrowed {
        return Ok(Some(decision.clone()));
    }
    let decision_id = text(decision.get("artifact_id"));
    let decision_hash = text(Some(saved_hash));
    let keep = match scope {
        Some("workspace") => {
            decision_id == Some(spec.artifact_id.as_str())
                && decision_hash.is_none_or(|hash| hash == spec.artifact_hash)
        }
        Some("harness" | "global") => {
            let id = Some(spec.artifact_id.as_str());
            let portable = runtime_tool_action_portable_match_context(context);
            let keys: Vec<String> = [
                runtime_scoped_exact_match_key(id, None),
                runtime_scoped_exact_match_key(id, context),
                runtime_scoped_exact_match_key(id, portable.as_deref()),
            ]
            .into_iter()
            .flatten()
            .collect();
            if keys.is_empty() {
                decision_id.is_some()
            } else {
                decision_hash.is_some_and(|hash| keys.iter().any(|key| key == hash))
            }
        }
        _ => false,
    };
    Ok(keep.then(|| decision.clone()))
}

#[cfg(test)]
#[path = "policy_runtime_saved_tests.rs"]
mod tests;
