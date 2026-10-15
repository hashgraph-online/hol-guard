//! The daemon's saved exact-action decision for a reviewed `PreToolUse`.
//!
//! When the edge asks for a review, the daemon first applies a decision the
//! user saved for this exact action: an "always block" blocks it, and an
//! "always allow" from the approval gate allows a review it may override.
//! This ports the steps of `pause_native_pre_tool_for_approval`
//! (`hook_native_review_approval.py`) up to `native_saved_review_response`
//! (`hook_native_saved_approval.py`) for the stores where those steps read
//! only local decisions that the bound integrity key verifies:
//!
//! - `native_review_policy_binding` (`hook_native_review_binding.py`) on the
//!   edge's own receipt;
//! - `native_exact_action` (`hook_native_exact_action.py`) with the process
//!   environment and extension-control digest the daemon published;
//! - the decision probe and the non-consuming `resolve_policy_decision_lookup`
//!   against the integrity state the daemon published, which must still be
//!   the stored one and protected, composed with the workspace's portable Git
//!   identity (`hook_direct_saved_portable.rs`);
//! - the block or accepted-allow response.
//!
//! Remote decisions need no more evidence than the daemon ships: the lookup
//! never serves a cloud-sync or team-policy row and verifies no remote row's
//! integrity, so the integrity key and state go only with a local decision.
//! Any other shape defers, so the daemon takes the request: custom grant
//! rows, portable decisions bound anywhere but the workspace's own identity,
//! a portable identity the resident does not resolve exactly, a policy
//! bundle with a policy-bundle row to match, an integrity state other than
//! the published protected one, a missing or unreadable decision, and every
//! step the daemon could answer differently.

use super::{reviewed_edge, HookDirectDefer, PRE_TOOL_USE};
use crate::local_store_read::{
    open_read_only, schema_version, table_exists, STORE_FILE_NAME, SUPPORTED_SCHEMA_VERSION,
};
use crate::policy_store::policy_store_direct_lane::DirectLaneBinding;
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_command::hook_responses::{pre_tool, Object};
use guard_contracts::{
    PolicyDecisionLookupRequestV1, HOOK_RENDER_MAX_BYTES, NATIVE_EXACT_ACTION_MAX_BYTES,
    POLICY_DECISION_LOOKUP_REQUEST_SCHEMA,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Map, Value};
use std::path::Path;
use zeroize::Zeroizing;

const REVIEW_ACTIONS: [&str; 2] = ["review", "require-reapproval"];
/// `GUARD_CONTROL_ACTION_TYPES` and `package`: never overridden by an allow.
const NON_OVERRIDABLE_ACTION_TYPES: [&str; 5] = [
    "guard_control",
    "guard-control",
    "guard_control_operation",
    "guard-control-operation",
    "package",
];
/// `REMOTE_POLICY_SOURCES` (`policy_integrity.py`).
const REMOTE_SOURCES_SQL: &str = "('cloud-sync', 'team-policy', 'policy-bundle', \
     'policy-bundle-canonical', 'cloud-signed-memory')";
const SAVED_BLOCK_REASON_CODE: &str = "saved_exact_action_block";
const SAVED_BLOCK_REASON: &str = "You chose to always block this exact action in HOL Guard.";
/// The worst-case growth of a request on the daemon's wire, where every byte
/// may become a six-byte escape, plus room for the envelope.
const ESCAPE_FACTOR: usize = 6;
const ENVELOPE_BYTES: usize = 1_024;

/// The request facts the daemon reads a saved decision with.
pub(super) struct Context<'a> {
    pub(super) harness: &'a str,
    pub(super) payload: &'a Map<String, Value>,
    /// The payload as the daemon records it: no `hook_env`, and the
    /// execution environment present even when the caller sent none.
    pub(super) recorded_payload: &'a Map<String, Value>,
    pub(super) workspace: &'a str,
    pub(super) home_dir: &'a str,
    pub(super) guard_home: &'a str,
    pub(super) binding: &'a DirectLaneBinding,
}

/// The edge result with the daemon's response, for a review the daemon
/// answers from a saved exact-action decision or an approve-once retry.
pub(super) fn answer(edge: &[u8], context: &Context<'_>) -> Result<Value, HookDirectDefer> {
    let mut parsed = reviewed_edge(edge, PRE_TOOL_USE)?;
    let result = parsed
        .get("result")
        .and_then(Value::as_object)
        .ok_or(HookDirectDefer::SavedDecision)?
        .clone();
    if !result
        .get("minimum_action")
        .and_then(Value::as_str)
        .is_some_and(|action| REVIEW_ACTIONS.contains(&action))
    {
        return Err(HookDirectDefer::NotAllow);
    }
    // A daemon that published no saved-decision state keeps every review.
    let binding = context.binding;
    let (Some(environment), Some(control_digest)) = (
        binding.exact_action_environment.as_ref(),
        binding.exact_action_control_digest.as_ref(),
    ) else {
        return Err(HookDirectDefer::NotAllow);
    };
    let input = query::QueryInput {
        harness: context.harness,
        payload: context.payload,
        workspace: context.workspace,
        home_dir: context.home_dir,
        environment: &environment.0,
        control_digest,
    };
    let receipt = parsed.get("receipt");
    let (artifact_id, exact) = query::exact_action(&input, &result, receipt)?;
    let encoded = serde_json::to_vec(&exact).map_err(|_| HookDirectDefer::SavedDecision)?;
    if encoded.len() * ESCAPE_FACTOR + ENVELOPE_BYTES > NATIVE_EXACT_ACTION_MAX_BYTES {
        return Err(HookDirectDefer::SavedDecision);
    }
    let token = crate::native_exact_action_op::exact_action_token(&exact);

    let store_path = Path::new(context.guard_home).join(STORE_FILE_NAME);
    {
        let connection = open_read_only(&store_path)
            .ok()
            .flatten()
            .ok_or(HookDirectDefer::SavedDecision)?;
        // One read snapshot for the shape checks and the lookup they gate, so
        // a decision or state the daemon commits between them cannot slip
        // past. It ends with this block, before the approve-once spend.
        let _snapshot = connection
            .unchecked_transaction()
            .map_err(|_| HookDirectDefer::SavedDecision)?;
        let store = StoreShape {
            connection: &connection,
            harness: context.harness,
            artifact_id: &artifact_id,
        };
        if !store.supported()? {
            return Err(HookDirectDefer::SavedDecision);
        }
        // A custom grant answers before any saved decision or approval, but
        // the daemon reads one only for a command that launches a local CLI.
        if store.grants()?
            && super::local_cli::launches_local_cli(
                context.payload,
                context.workspace,
                context.home_dir,
            )
            .unwrap_or(true)
        {
            return Err(HookDirectDefer::LocalCliRules);
        }
        match &token {
            Ok(token) if store.decided(Some(token))? => {
                let saved = saved_response(context, &store, &result, token)?;
                if let Some(response) = saved {
                    parsed["harness_response"] = response;
                    return Ok(parsed);
                }
            }
            Ok(_) => {}
            // A token the daemon may still derive could read a decision this
            // artifact holds, so only an undecided artifact skips the read.
            Err(_) if store.decided(None)? => return Err(HookDirectDefer::SavedDecision),
            Err(_) => {}
        }
    }
    parsed["harness_response"] =
        match consume::answer(context, &result, &exact, receipt, &artifact_id)? {
            Some(response) => response,
            None => review_queue::answer(context, &result, receipt, &exact, &token)?,
        };
    Ok(parsed)
}

/// `native_saved_decision_response` for a token with an exact decision: the
/// rendered verdict, or `None` when the decision leaves the review standing.
fn saved_response(
    context: &Context<'_>,
    store: &StoreShape<'_>,
    result: &Object,
    token: &str,
) -> Result<Option<Value>, HookDirectDefer> {
    let binding = context.binding;
    let (Some(integrity), Some(key)) = (
        binding.policy_integrity_state.as_ref(),
        binding.integrity_key.as_ref(),
    ) else {
        return Err(HookDirectDefer::SavedDecision);
    };
    if integrity.enforcement != "enforce"
        || integrity.mode != "protected"
        || !integrity.cutover_complete
        || !integrity.degraded_reasons.is_empty()
        || integrity.generation.is_none()
        || integrity.key_id.as_deref() != Some(key.key_id.as_str())
    {
        return Err(HookDirectDefer::SavedDecision);
    }
    let integrity_state =
        serde_json::to_value(integrity).map_err(|_| HookDirectDefer::SavedDecision)?;
    let Some(has_local_policy) = store.readable(&integrity_state)? else {
        return Err(HookDirectDefer::SavedDecision);
    };
    let identity = portable::identity(store, context.workspace)?;
    let key_b64 = Zeroizing::new(Base64UrlUnpadded::encode_string(&key.key));
    let store_path = Path::new(context.guard_home).join(STORE_FILE_NAME);
    let request = PolicyDecisionLookupRequestV1 {
        schema: POLICY_DECISION_LOOKUP_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        store_path: store_path.to_string_lossy().into_owned(),
        guard_home: context.guard_home.to_owned(),
        harness: context.harness.to_owned(),
        artifact_id: Some(store.artifact_id.to_owned()),
        artifact_hash: Some(token.to_owned()),
        workspace: Some(context.workspace.to_owned()),
        publisher: None,
        now: super::lifecycle::utc_now_isoformat().ok_or(HookDirectDefer::SavedDecision)?,
        runtime_exact_match_context: None,
        consume_one_shot: false,
        local_once_only: false,
        integrity_state: Some(if has_local_policy {
            integrity_state
        } else {
            json!({})
        }),
        integrity_key_b64: has_local_policy.then(|| key_b64.to_string()),
        integrity_key_id: has_local_policy.then(|| key.key_id.clone()),
        local_once_integrity_key_b64: Some(key_b64.to_string()),
        local_once_integrity_key_id: Some(key.key_id.clone()),
        policy_bundle_decision_identities: None,
        probe_groups: None,
    };
    let lookup = |workspace: &str| {
        let request = PolicyDecisionLookupRequestV1 {
            workspace: Some(workspace.to_owned()),
            ..request.clone()
        };
        crate::policy_decision_lookup_op::evaluate_non_consuming(&request, store.connection)
            .map_err(|_| HookDirectDefer::SavedDecision)
    };
    let local = lookup(context.workspace)?;
    let lookup = match identity {
        None => local,
        Some(identity) => portable::compose(local, lookup(&identity)?)?,
    };
    match saved_verdict(result, &lookup, store.artifact_id, token) {
        Some((verdict, status)) => render(context.harness, &verdict, status)
            .map(Some)
            .ok_or(HookDirectDefer::SavedDecision),
        None => Ok(None),
    }
}

/// `native_saved_decision_response` after its lookup: the verdict to render
/// and its reuse status for a qualifying decision, `None` for every other
/// outcome.
fn saved_verdict(
    result: &Object,
    lookup: &Value,
    artifact_id: &str,
    token: &str,
) -> Option<(Object, &'static str)> {
    if !lookup.is_object() || truthy(lookup.get("ignored_local_integrity")) {
        return None;
    }
    let decision = lookup.get("decision")?.as_object()?;
    if decision.get("scope").and_then(Value::as_str) != Some("artifact")
        || decision.get("artifact_id").and_then(Value::as_str) != Some(artifact_id)
        || decision.get("artifact_hash").and_then(Value::as_str) != Some(token)
    {
        return None;
    }
    match decision.get("action").and_then(Value::as_str) {
        Some("block") => {
            let mut blocked = result.clone();
            for (key, value) in [
                ("decision", "deny"),
                ("minimum_action", "block"),
                ("policy_action", "block"),
                ("reason_code", SAVED_BLOCK_REASON_CODE),
                ("reason", SAVED_BLOCK_REASON),
            ] {
                blocked.insert(key.to_owned(), json!(value));
            }
            Some((blocked, "blocked"))
        }
        Some("allow")
            if decision.get("source").and_then(Value::as_str) == Some("approval-gate")
                && !truthy(decision.get("expires_at"))
                && overridable(result) =>
        {
            let mut allowed = result.clone();
            for key in ["decision", "minimum_action", "policy_action"] {
                allowed.insert(key.to_owned(), json!("allow"));
            }
            Some((allowed, "accepted"))
        }
        _ => None,
    }
}

/// The rendered verdict marked with its reuse status, or `None` when the
/// daemon's render request could exceed its size limit.
fn render(harness: &str, verdict: &Object, status: &str) -> Option<Value> {
    let encoded = serde_json::to_vec(verdict).ok()?.len() + harness.len();
    if encoded * ESCAPE_FACTOR + ENVELOPE_BYTES > HOOK_RENDER_MAX_BYTES {
        return None;
    }
    let mut response = pre_tool(harness, verdict);
    response.insert("approval_reuse_status".to_owned(), json!(status));
    Some(Value::Object(response))
}

/// `_native_review_is_overridable`. An unhashable action type, which raises
/// there, is never overridable here.
fn overridable(result: &Object) -> bool {
    let review = |key: &str| {
        result
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|action| REVIEW_ACTIONS.contains(&action))
    };
    let action_type = result
        .get("action")
        .and_then(Value::as_object)
        .and_then(|action| action.get("action_type"));
    let overridable_type = match action_type {
        Some(Value::String(kind)) => !NON_OVERRIDABLE_ACTION_TYPES.contains(&kind.as_str()),
        Some(Value::Array(_) | Value::Object(_)) => false,
        _ => true,
    };
    review("policy_action") && review("minimum_action") && overridable_type
}

/// Python truthiness of an optional JSON value.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(fields)) => !fields.is_empty(),
    }
}

/// The store, as the daemon's lookup would read it.
struct StoreShape<'a> {
    connection: &'a Connection,
    harness: &'a str,
    artifact_id: &'a str,
}

impl StoreShape<'_> {
    /// Whether the daemon reads this store's decisions as the resident does:
    /// a schema it supports.
    fn supported(&self) -> Result<bool, HookDirectDefer> {
        let unavailable = |_| HookDirectDefer::SavedDecision;
        Ok(matches!(
            schema_version(self.connection).map_err(unavailable)?,
            Some(version) if version <= SUPPORTED_SCHEMA_VERSION
        ))
    }

    /// Whether the store holds any custom grant or block rule.
    fn grants(&self) -> Result<bool, HookDirectDefer> {
        let unavailable = |_| HookDirectDefer::SavedDecision;
        for table in ["local_cli_grant", "local_cli_command_grant"] {
            if table_exists(self.connection, table).map_err(unavailable)?
                && self.any(&format!("select 1 from {table} limit 1"), &[])?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// The daemon's decision probe for `token`, or for any token when the
    /// resident could not derive one.
    fn decided(&self, token: Option<&str>) -> Result<bool, HookDirectDefer> {
        let artifact = "select 1 from policy_decisions where harness in (?1, '*') \
                        and scope = 'artifact' and artifact_id = ?2";
        match token {
            Some(token) => self.any(
                &format!("{artifact} and artifact_hash = ?3 limit 1"),
                &[self.harness, self.artifact_id, token],
            ),
            None => self.any(
                &format!("{artifact} limit 1"),
                &[self.harness, self.artifact_id],
            ),
        }
    }

    /// Whether the store holds a local decision, when the daemon's lookup
    /// reads it under the published integrity state: no cached policy bundle
    /// with a policy-bundle row to match, since the bundle's decision
    /// identities come from a synced payload the resident does not validate,
    /// and the published state still stored. `None` otherwise.
    /// Portable decisions are read through the workspace's identity
    /// (`portable::identity`).
    fn readable(&self, integrity_state: &Value) -> Result<Option<bool>, HookDirectDefer> {
        if self.any(
            "select 1 from policy_decisions where source = 'policy-bundle' limit 1",
            &[],
        )? && self.any(
            "select 1 from sync_state where state_key = 'policy_bundle' limit 1",
            &[],
        )? {
            return Ok(None);
        }
        let has_local_policy = self.any(
            &format!(
                "select 1 from policy_decisions where source not in {REMOTE_SOURCES_SQL} limit 1"
            ),
            &[],
        )?;
        let stored: Option<String> = self
            .connection
            .query_row(
                "select payload_json from sync_state where state_key = 'policy_integrity'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| HookDirectDefer::SavedDecision)?;
        let stored = stored.and_then(|text| serde_json::from_str::<Value>(&text).ok());
        Ok((stored.as_ref() == Some(integrity_state)).then_some(has_local_policy))
    }

    fn any(&self, query: &str, values: &[&str]) -> Result<bool, HookDirectDefer> {
        self.connection
            .query_row(query, rusqlite::params_from_iter(values.iter()), |_| Ok(()))
            .optional()
            .map(|found| found.is_some())
            .map_err(|_| HookDirectDefer::SavedDecision)
    }
}

#[path = "hook_direct_saved_query.rs"]
mod query;

#[path = "hook_direct_saved_consume.rs"]
mod consume;

#[path = "hook_direct_saved_portable.rs"]
mod portable;

// Read once the direct lane queues a reviewed `PreToolUse` itself.
#[path = "hook_direct_review_request.rs"]
mod review_request;

#[path = "hook_direct_review_queue.rs"]
mod review_queue;

#[cfg(test)]
#[path = "hook_direct_saved_decision_tests.rs"]
mod tests;
