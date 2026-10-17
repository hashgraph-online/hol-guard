//! `PolicyDocumentDecide` - decide one event against the compiled rows of a
//! policy document and explain every rule that was considered.
//!
//! `policy check` and `policy test` answer the question the runtime answers
//! from the store: which rule decides this event, and why every other rule
//! lost. Two implementations of that answer can drift, and a document path
//! that is more permissive than the store is a silent hole, so the precedence,
//! expiry and exact-match rules live here beside the store lookup and reuse
//! its ranking helpers rather than restating them.
//!
//! Pure: the caller ships the rows it compiled, and the op never opens the
//! store, the keyring or a policy file.

use guard_contracts::{
    canonical_policy_timestamp_nanos, PolicyDocumentDecisionRequestV1,
    PolicyDocumentDecisionResultV1, PolicyDocumentEventV1, PolicyDocumentRowV1,
    APPROVAL_CONTEXT_TOKEN_PREFIX, POLICY_DOCUMENT_DECISION_MAX_BYTES,
    POLICY_DOCUMENT_DECISION_MAX_ROWS, POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA,
    POLICY_DOCUMENT_DECISION_RESULT_SCHEMA, POLICY_DOCUMENT_MATCH_LIMIT,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;
use crate::policy_decision_lookup_op::{
    artifact_family_key, policy_row_outranks, policy_row_specificity,
    runtime_scoped_exact_match_key, workspace_policy_key, SCOPED_APPROVAL_FAMILIES,
    SCOPED_RUNTIME_EXACT_FAMILIES,
};

#[cfg(test)]
#[path = "policy_document_decide_op_tests.rs"]
mod tests;

const SCOPES: [&str; 5] = ["artifact", "workspace", "publisher", "harness", "global"];

/// The lookup keys one event probes with, derived once for the whole decision.
struct Keys {
    harness: String,
    artifact_id: Option<String>,
    family_key: Option<String>,
    workspace: Option<String>,
    workspace_key: Option<String>,
    publisher: Option<String>,
    at: String,
    at_nanos: i128,
}

pub(crate) fn evaluate_policy_document_decision_request(
    request: &PolicyDocumentDecisionRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, POLICY_DOCUMENT_DECISION_MAX_BYTES)
        .map_err(|_| "native_policy_document_decision_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&PolicyDocumentDecisionResultV1 {
        schema: POLICY_DOCUMENT_DECISION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &PolicyDocumentDecisionRequestV1) -> Result<Value, String> {
    // A request that names another schema was built against another contract;
    // deciding it anyway would answer a question nobody asked.
    if request.schema != POLICY_DOCUMENT_DECISION_REQUEST_SCHEMA {
        return Err("native_policy_document_decision_schema_mismatch".to_owned());
    }
    if request.rows.len() > POLICY_DOCUMENT_DECISION_MAX_ROWS {
        return Err("native_policy_document_decision_too_large".to_owned());
    }
    for row in &request.rows {
        if row.rule_id.is_empty() || row.harness.is_empty() {
            return Err("native_policy_document_decision_row_invalid".to_owned());
        }
        if !SCOPES.contains(&row.scope.as_str()) {
            return Err("native_policy_document_decision_row_scope_unknown".to_owned());
        }
        // The lattice ranks more actions than a document can compile; refusing
        // the rest keeps the ranking here identical to the store's.
        if row.action != "allow" && row.action != "block" {
            return Err("native_policy_document_decision_row_action_unknown".to_owned());
        }
    }
    if request.event.harness.is_empty() {
        return Err("native_policy_document_decision_event_invalid".to_owned());
    }
    let keys = lookup_keys(&request.event, &request.now)?;
    Ok(decide(&request.rows, &keys))
}

/// `tool_family_artifact_id` - the family artifact a tool event probes with.
fn tool_family_artifact_id(tool: &str) -> Option<String> {
    let normalized = tool.to_lowercase();
    if normalized == "shell" {
        return Some("family:tool-action".to_owned());
    }
    SCOPED_APPROVAL_FAMILIES
        .contains(&normalized.as_str())
        .then(|| format!("family:{normalized}"))
}

/// `_lookup_keys` - an event names an artifact or a tool family, never both.
fn lookup_keys(event: &PolicyDocumentEventV1, now: &str) -> Result<Keys, String> {
    let at = match event.at.as_deref() {
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => now.to_owned(),
    };
    let at_nanos = canonical_policy_timestamp_nanos(&at)
        .ok_or_else(|| "native_policy_document_decision_time_invalid".to_owned())?;
    let artifact_id = match event.artifact.as_deref() {
        Some(artifact) if !artifact.is_empty() => Some(artifact.to_owned()),
        _ => event.tool.as_deref().and_then(tool_family_artifact_id),
    };
    Ok(Keys {
        harness: event.harness.clone(),
        family_key: artifact_family_key(artifact_id.as_deref()),
        artifact_id,
        workspace_key: workspace_policy_key(event.workspace.as_deref()),
        workspace: event.workspace.clone(),
        publisher: event.publisher.clone(),
        at,
        at_nanos,
    })
}

/// `_legacy_hash` - a row that carries no approval-context token is not bound
/// to one request's context, so it still answers a plain selector probe.
fn legacy_hash(artifact_hash: Option<&str>) -> bool {
    match artifact_hash {
        None => true,
        Some(value) => !value.starts_with(APPROVAL_CONTEXT_TOKEN_PREFIX),
    }
}

/// `_artifact_selector_matches`.
fn artifact_selector_matches(row: &PolicyDocumentRowV1, keys: &Keys, legacy_only: bool) -> bool {
    let Some(selector) = row.artifact_id.as_deref() else {
        return true;
    };
    if Some(selector) != keys.artifact_id.as_deref() && Some(selector) != keys.family_key.as_deref()
    {
        return false;
    }
    if legacy_only {
        row.artifact_hash.is_none()
    } else {
        legacy_hash(row.artifact_hash.as_deref())
    }
}

/// `_mismatch` - the first probe field the row fails on, or `None` when the
/// row answers this event's probe.
fn mismatch(row: &PolicyDocumentRowV1, keys: &Keys) -> Option<&'static str> {
    if row.harness != keys.harness && row.harness != "*" {
        return Some("harness");
    }
    match row.scope.as_str() {
        "artifact" => {
            let matched = keys.artifact_id.is_some()
                && row.artifact_id.as_deref() == keys.artifact_id.as_deref()
                && row.artifact_hash.is_none();
            (!matched).then_some("artifact")
        }
        "workspace" => {
            let stored = workspace_policy_key(row.workspace.as_deref());
            let matched = match stored.as_deref() {
                None => false,
                Some(key) => {
                    Some(key) == keys.workspace_key.as_deref()
                        || Some(key) == keys.workspace.as_deref()
                }
            };
            if !matched {
                return Some("workspace");
            }
            (!artifact_selector_matches(row, keys, true)).then_some("artifact")
        }
        "publisher" => {
            if keys.publisher.is_none() || row.publisher.as_deref() != keys.publisher.as_deref() {
                return Some("publisher");
            }
            (!legacy_hash(row.artifact_hash.as_deref())).then_some("artifact")
        }
        _ => (!artifact_selector_matches(row, keys, false)).then_some("artifact"),
    }
}

/// `_requires_exact_match` - a broad rule over an exact-only family only binds
/// the one artifact its runtime exact-match key names.
///
/// The key comes from the store lookup's own helper, so a document rule and a
/// stored approval cannot disagree about which artifact a hash names.
fn requires_exact_match(row: &PolicyDocumentRowV1, keys: &Keys) -> bool {
    if row.scope != "harness" && row.scope != "global" {
        return false;
    }
    let Some(family_key) = artifact_family_key(row.artifact_id.as_deref()) else {
        return false;
    };
    let family = family_key.strip_prefix("family:").unwrap_or(&family_key);
    if !SCOPED_RUNTIME_EXACT_FAMILIES.contains(&family) {
        return false;
    }
    match runtime_scoped_exact_match_key(keys.artifact_id.as_deref(), None) {
        None => true,
        Some(expected) => expected != row.artifact_hash.clone().unwrap_or_default(),
    }
}

/// `_is_expired` - an expiry the parser rejects expires the row, so an
/// unreadable deadline can never keep a rule alive.
fn is_expired(row: &PolicyDocumentRowV1, at_nanos: i128) -> bool {
    match row.expires_at.as_deref() {
        None => false,
        Some(value) => match canonical_policy_timestamp_nanos(value) {
            None => true,
            Some(expires) => expires <= at_nanos,
        },
    }
}

/// `_PROBE_ORDER` - the order the store probes scopes in.
fn probe_order(scope: &str) -> u8 {
    match scope {
        "artifact" => 0,
        "workspace" => 1,
        "publisher" => 2,
        "harness" => 3,
        _ => 4,
    }
}

/// `_classify` - why each row did or did not reach the ranking.
fn classify(
    rows: &[PolicyDocumentRowV1],
    keys: &Keys,
) -> Vec<(&'static str, Option<&'static str>)> {
    rows.iter()
        .map(|row| {
            if let Some(failed) = mismatch(row, keys) {
                ("unmatched", Some(failed))
            } else if is_expired(row, keys.at_nanos) {
                ("expired", Some("expired"))
            } else if requires_exact_match(row, keys) {
                ("not_enforced", Some("exact_only_family"))
            } else {
                ("matched", None)
            }
        })
        .collect()
}

/// `_pick_winner` - probe order decides who is compared first; block beats
/// allow, then the more specific row wins.
fn pick_winner(
    values: &[Value],
    rows: &[PolicyDocumentRowV1],
    matched: &[usize],
    keys: &Keys,
) -> Option<usize> {
    let mut ordered = matched.to_vec();
    ordered.sort_by_key(|&index| {
        (
            probe_order(&rows[index].scope),
            u8::from(rows[index].harness != keys.harness),
            index,
        )
    });
    let mut winner: Option<usize> = None;
    for index in ordered {
        match winner {
            None => winner = Some(index),
            Some(current) => {
                if policy_row_outranks(&values[index], &values[current], &keys.harness) {
                    winner = Some(index);
                }
            }
        }
    }
    winner
}

fn decide(rows: &[PolicyDocumentRowV1], keys: &Keys) -> Value {
    let values: Vec<Value> = rows
        .iter()
        .map(|row| serde_json::to_value(row).unwrap_or(Value::Null))
        .collect();
    let states = classify(rows, keys);
    let matched: Vec<usize> = states
        .iter()
        .enumerate()
        .filter_map(|(index, (state, _))| (*state == "matched").then_some(index))
        .collect();
    let winner = pick_winner(&values, rows, &matched, keys);
    let winning_specificity =
        winner.map(|index| policy_row_specificity(&values[index], &keys.harness));

    let mut tied: Vec<String> = Vec::new();
    let mut candidates: Vec<Value> = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let (mut state, mut reason) = states[index];
        if state == "matched" {
            if Some(index) == winner {
                state = "selected";
                reason = None;
            } else {
                state = "outranked";
                reason = Some("more_specific_rule");
                if let (Some(winner_index), Some(winner_specificity)) =
                    (winner, winning_specificity)
                {
                    if rows[winner_index].action != row.action {
                        reason = Some("block_wins");
                    } else if policy_row_specificity(&values[index], &keys.harness)
                        == winner_specificity
                        && row.rule_id != rows[winner_index].rule_id
                    {
                        reason = Some("tie");
                        if !tied.contains(&row.rule_id) {
                            tied.push(row.rule_id.clone());
                        }
                    }
                }
            }
        }
        candidates.push(json!({
            "ruleId": row.rule_id,
            "rowIndex": index,
            "state": state,
            "reason": reason,
        }));
    }
    tied.sort();
    let lookup = json!({
        "artifactId": keys.artifact_id,
        "familyKey": keys.family_key,
        "at": keys.at,
    });
    // The store stops fetching past the probe limit, so a document that would
    // have pushed it past that limit decides nothing and blocks.
    let fetched = states
        .iter()
        .filter(|(state, _)| *state == "matched" || *state == "not_enforced")
        .count();
    if fetched > POLICY_DOCUMENT_MATCH_LIMIT {
        return json!({
            "effect": "block",
            "ruleId": Value::Null,
            "ambiguous": false,
            "matchLimitExceeded": true,
            "tiedRuleIds": Vec::<String>::new(),
            "candidates": candidates,
            "lookup": lookup,
        });
    }
    json!({
        "effect": winner.map_or("default", |index| rows[index].action.as_str()),
        "ruleId": winner.map(|index| rows[index].rule_id.clone()),
        "ambiguous": !tied.is_empty(),
        "matchLimitExceeded": false,
        "tiedRuleIds": tied,
        "candidates": candidates,
        "lookup": lookup,
    })
}
