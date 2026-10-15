//! In-process saved-policy lookup for the MCP tool-call decide op.
//!
//! This is the resident side of `resolve_policy_decision_lookup_with_memory_pattern`
//! for a non-consuming call: one probe per candidate artifact id through the
//! `policy_decision_lookup` engine on a single store connection, the portable
//! Git-workspace composition, and the most-restrictive choice. The caller ships
//! the keyring-facing integrity evidence once; nothing here consumes a
//! one-shot approval or writes the store.

use guard_contracts::{
    McpPolicyLookupInputV1, McpToolPolicySubjectV1, PolicyDecisionLookupRequestV1,
    POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::context_digest::python_strip;
use crate::local_store_read::require_store_path;
use crate::mcp_tool_policy_flow::Stop;
use crate::policy_decision_lookup_op::{evaluate_non_consuming, open_lookup_connection};

pub(crate) const ERR_LOOKUP: &str = "native_mcp_tool_policy_decide_lookup_failed";
const MAX_CANDIDATES: usize = 8;
const REVIEW_FLOOR: u8 = 2;

/// Rank of a saved action; an unrecognized action ranks as `block`.
pub(crate) fn severity(action: Option<&Value>) -> u8 {
    match action.and_then(Value::as_str) {
        Some("allow") => 0,
        Some("warn") => 1,
        Some("review" | "ask") => 2,
        Some("require-reapproval") => 3,
        Some("sandbox-required") => 4,
        _ => 5,
    }
}

fn field<'a>(lookup: &'a Value, key: &str) -> &'a Value {
    lookup.get(key).unwrap_or(&Value::Null)
}

/// Compose probes: the most restrictive decision wins, the first one wins a tie.
pub(crate) fn most_restrictive(lookups: &[Value]) -> Option<Value> {
    let first = lookups.first()?;
    let mut selected = first;
    let mut ignored = field(first, "ignored_local_integrity").clone();
    let mut revisions: Vec<&Value> = Vec::new();
    for lookup in lookups {
        let revision = field(lookup, "authority_revision");
        if !revisions.contains(&revision) {
            revisions.push(revision);
        }
    }
    let authority_revision = if revisions.len() == 1 {
        revisions[0].clone()
    } else {
        json!(-1)
    };
    for lookup in &lookups[1..] {
        if ignored.is_null() && !field(lookup, "ignored_local_integrity").is_null() {
            ignored = field(lookup, "ignored_local_integrity").clone();
        }
        let decision = field(lookup, "decision");
        if decision.is_null() {
            continue;
        }
        let current = field(selected, "decision");
        if current.is_null() || severity(decision.get("action")) > severity(current.get("action")) {
            selected = lookup;
        }
    }
    let mut decision = field(selected, "decision").clone();
    if let Value::Object(row) = &mut decision {
        row.insert(
            "_approval_authority_revision".to_owned(),
            authority_revision.clone(),
        );
    }
    Some(json!({
        "decision": decision,
        "ignored_local_integrity": ignored,
        "trust_status": field(selected, "trust_status"),
        "authority_revision": authority_revision,
    }))
}

/// A portable selector is restrictive-only: it never lowers enforcement below
/// review and never carries one-shot authority.
pub(crate) fn without_permission_elevation(lookup: Value) -> Value {
    let Some(decision) = lookup.get("decision").and_then(Value::as_object) else {
        return lookup;
    };
    let one_shot = decision.get("approval_id").is_some_and(|id| !id.is_null());
    if one_shot || severity(decision.get("action")) < REVIEW_FLOOR {
        let mut cleared: Map<String, Value> = lookup.as_object().cloned().unwrap_or_default();
        cleared.insert("decision".to_owned(), Value::Null);
        return Value::Object(cleared);
    }
    lookup
}

struct Prober<'a> {
    input: &'a McpPolicyLookupInputV1,
    subject: &'a McpToolPolicySubjectV1,
    exact_match_context: Option<String>,
    connection: Option<rusqlite::Connection>,
}

impl Prober<'_> {
    fn probe(&self, artifact_id: &str, workspace: Option<&str>) -> Result<Value, &'static str> {
        if let Some(trust) = &self.input.degraded_trust_status {
            return Ok(json!({
                "decision": null,
                "ignored_local_integrity": null,
                "trust_status": trust,
                "authority_revision": -1,
            }));
        }
        let connection = self.connection.as_ref().ok_or(ERR_LOOKUP)?;
        let input = self.input;
        let request = PolicyDecisionLookupRequestV1 {
            schema: POLICY_DECISION_LOOKUP_REQUEST_SCHEMA.to_owned(),
            request_id: String::new(),
            store_path: input.store_path.clone(),
            guard_home: input.guard_home.clone(),
            harness: self.subject.harness.clone(),
            artifact_id: Some(artifact_id.to_owned()),
            artifact_hash: Some(self.subject.artifact_hash.clone()),
            workspace: workspace.map(str::to_owned),
            publisher: self.subject.publisher.clone(),
            now: input.now.clone(),
            runtime_exact_match_context: self.exact_match_context.clone(),
            consume_one_shot: false,
            local_once_only: false,
            integrity_state: input.integrity_state.clone(),
            integrity_key_b64: input.integrity_key_b64.clone(),
            integrity_key_id: input.integrity_key_id.clone(),
            local_once_integrity_key_b64: input.local_once_integrity_key_b64.clone(),
            local_once_integrity_key_id: input.local_once_integrity_key_id.clone(),
            policy_bundle_decision_identities: input.policy_bundle_decision_identities.clone(),
            probe_groups: None,
        };
        evaluate_non_consuming(&request, connection).map_err(|_| ERR_LOOKUP)
    }

    /// One candidate, with the portable Git-workspace authority composed in.
    fn candidate(&self, artifact_id: &str) -> Result<Value, &'static str> {
        let workspace = self.subject.workspace.as_deref();
        let Some(portable) = self.input.portable_workspace.as_deref() else {
            return self.probe(artifact_id, workspace);
        };
        let preview = without_permission_elevation(self.probe(artifact_id, Some(portable))?);
        if workspace.map(python_strip) == Some(portable) {
            return Ok(preview);
        }
        let local = self.probe(artifact_id, workspace)?;
        most_restrictive(&[local, preview]).ok_or(ERR_LOOKUP)
    }
}

/// The `policy_lookup` observation for the initial pass, read in-process.
pub(crate) fn policy_lookup(
    input: &McpPolicyLookupInputV1,
    subject: &McpToolPolicySubjectV1,
    exact_match_context: Option<String>,
) -> Result<Value, Stop> {
    let ids = &input.candidate_artifact_ids;
    if ids.is_empty()
        || ids.len() > MAX_CANDIDATES
        || ids.first().map(String::as_str) != Some(subject.artifact_id.as_str())
    {
        return Err(Stop::Fail(ERR_LOOKUP));
    }
    let connection = if input.degraded_trust_status.is_some() {
        None
    } else {
        require_store_path(&input.store_path, &input.guard_home).map_err(|_| ERR_LOOKUP)?;
        Some(open_lookup_connection(&input.store_path).map_err(|_| ERR_LOOKUP)?)
    };
    let prober = Prober {
        input,
        subject,
        exact_match_context,
        connection,
    };
    let mut lookups = Vec::with_capacity(ids.len());
    for id in ids {
        lookups.push(prober.candidate(id)?);
    }
    let composed = most_restrictive(&lookups).ok_or(ERR_LOOKUP)?;
    let decision = field(&composed, "decision").clone();
    let ignored = !field(&composed, "ignored_local_integrity").is_null();
    let mut observed = json!({"decision": decision, "ignored_local_integrity": ignored});
    if observed["decision"].is_null() && !ignored && input.diagnostic_empty {
        observed["reuse_diagnostic"] = json!({"reason": null});
    }
    Ok(observed)
}

#[cfg(test)]
#[path = "mcp_tool_policy_lookup_tests.rs"]
mod tests;
