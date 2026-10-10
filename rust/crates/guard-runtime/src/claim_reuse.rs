//! The atomic saved-allow claim transaction (`GuardStore.claim_approval_reuse_decisions`).
//!
//! One `BEGIN IMMEDIATE` covers the whole batch so a denied launch cannot
//! consume a sibling grant. Two member shapes: `approval_id` selects a
//! `guard_local_once_approvals` row, `decision_id` selects a `policy_decisions`
//! row. Every identity key the evaluator observed must still match the locked
//! row; any mismatch rolls the entire batch back.
//!
//! The OS-keyring-facing evidence (integrity state, HMAC key material,
//! materialized policy-bundle identities) is shipped by the caller as
//! [`ClaimEvidence`]; this module never resolves secrets itself.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::policy_decision_lookup_op::{
    claim_local_once_by_id, materialized_policy_bundle_row_identity,
    policy_integrity_result_for_row, policy_row_payload, policy_row_to_json, row_value,
    LOCAL_ONCE_LEGACY_AUTHORITY_KIND, POLICY_LOOKUP_COLUMNS,
};
use guard_policy_snapshot::policy_integrity::{
    is_remote_policy_source, PolicyIntegrityVerification,
};

/// Policy sources a reuse claim must never consume.
const NON_REUSABLE_REMOTE_SOURCES: [&str; 2] = ["cloud-sync", "team-policy"];

/// The identity keys compared against the selected allow. `integrity_message`
/// is part of the payload but deliberately not part of the comparison.
const IDENTITY_KEYS: [&str; 20] = [
    "action",
    "artifact_hash",
    "artifact_id",
    "decision_id",
    "expires_at",
    "harness",
    "integrity_enforcement",
    "integrity_generation",
    "integrity_key_id",
    "integrity_mode",
    "integrity_status",
    "integrity_version",
    "owner",
    "publisher",
    "reason",
    "scope",
    "signed_at",
    "source",
    "updated_at",
    "workspace",
];

/// Caller-shipped integrity evidence for one claim.
pub struct ClaimEvidence<'a> {
    pub integrity_state: Option<&'a Value>,
    pub integrity_key: Option<&'a [u8]>,
    pub integrity_key_id: Option<&'a str>,
    pub local_once_key: Option<&'a [u8]>,
    pub local_once_key_id: Option<&'a str>,
    pub policy_bundle_identities: Option<&'a [Vec<Value>]>,
}

/// The singleton revision used to detect a concurrent authority change between
/// evaluation and claim. A missing or non-integer row is `-1`, which no valid
/// claim (revision >= 0) can match.
pub fn approval_authority_revision(connection: &Connection) -> rusqlite::Result<i64> {
    let revision: Option<Option<i64>> = connection
        .query_row(
            "select revision from guard_approval_authority_revision where singleton = 1",
            [],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()?;
    Ok(revision.flatten().unwrap_or(-1))
}

pub fn approval_reuse_claim_disposition(decision: &Value) -> Option<&'static str> {
    crate::approval_proof_op::claim_disposition(decision.as_object()?).map(|d| d.as_str())
}

fn text_non_empty<'a>(decision: &'a Value, key: &str) -> Option<&'a str> {
    decision
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn integer_id(decision: &Value, key: &str) -> Option<i64> {
    match decision.get(key) {
        Some(Value::Number(number)) if !number.is_f64() => number.as_i64(),
        _ => None,
    }
}

/// Validate and dedupe the batch. `Err(())` means the batch is not claimable.
fn unique_members(decisions: &[Value]) -> Result<(Vec<&Value>, i64), ()> {
    let mut unique: Vec<&Value> = Vec::new();
    let mut seen: Vec<(&'static str, String)> = Vec::new();
    let mut expected_revision: Option<i64> = None;
    for decision in decisions {
        if decision.get("action").and_then(Value::as_str) != Some("allow") {
            return Err(());
        }
        let revision = integer_id(decision, "_approval_authority_revision").ok_or(())?;
        if revision < 0 {
            return Err(());
        }
        match expected_revision {
            None => expected_revision = Some(revision),
            Some(expected) if expected != revision => return Err(()),
            Some(_) => {}
        }
        let key = if let Some(approval_id) = text_non_empty(decision, "approval_id") {
            ("approval", approval_id.to_owned())
        } else if let Some(decision_id) = integer_id(decision, "decision_id") {
            ("policy", decision_id.to_string())
        } else {
            return Err(());
        };
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        unique.push(decision);
    }
    Ok((unique, expected_revision.unwrap_or(-1)))
}

fn insert_event(
    connection: &Connection,
    name: &str,
    payload: &Value,
    now: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "insert into guard_events (event_name, payload_json, occurred_at) values (?1, ?2, ?3)",
        params![name, payload.to_string(), now],
    )?;
    Ok(())
}

fn claim_local_once_member(
    connection: &Connection,
    decision: &Value,
    approval_id: &str,
    disposition: &str,
    now: &str,
    evidence: &ClaimEvidence<'_>,
) -> rusqlite::Result<bool> {
    if decision.get("authority_kind").and_then(Value::as_str)
        != Some(LOCAL_ONCE_LEGACY_AUTHORITY_KIND)
    {
        return Ok(false);
    }
    let Some(claimed) = claim_local_once_by_id(
        connection,
        approval_id,
        now,
        evidence.local_once_key,
        evidence.local_once_key_id,
        disposition == "consumed",
        Some(decision),
    )?
    else {
        return Ok(false);
    };
    let event = if disposition == "retained" {
        "approval.local_once_reused"
    } else {
        "approval.local_once_applied"
    };
    insert_event(
        connection,
        event,
        &json!({
            "approval_id": row_value(&claimed, "approval_id"),
            "request_id": row_value(&claimed, "request_id"),
            "harness": row_value(&claimed, "harness"),
            "artifact_id": row_value(&claimed, "artifact_id"),
        }),
        now,
    )?;
    Ok(true)
}

fn row_integrity(
    row: &Value,
    source: &str,
    evidence: &ClaimEvidence<'_>,
) -> (PolicyIntegrityVerification, Option<Value>) {
    if is_remote_policy_source(Some(source)) {
        let result = policy_integrity_result_for_row(row, "protected", None, None, None);
        return (result, None);
    }
    let state = evidence
        .integrity_state
        .cloned()
        .unwrap_or_else(|| json!({}));
    let generation = match state.get("generation") {
        Some(Value::Number(number)) if !number.is_f64() => number.as_i64(),
        _ => None,
    };
    let mode = state
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("degraded");
    let result = policy_integrity_result_for_row(
        row,
        mode,
        evidence.integrity_key,
        evidence.integrity_key_id,
        generation,
    );
    (result, Some(state))
}

fn claim_policy_member(
    connection: &Connection,
    decision: &Value,
    decision_id: i64,
    disposition: &str,
    now: &str,
    evidence: &ClaimEvidence<'_>,
) -> rusqlite::Result<bool> {
    let sql = format!(
        "select {POLICY_LOOKUP_COLUMNS} from policy_decisions where decision_id = ?1 \
         and action = 'allow' and (expires_at is null or julianday(expires_at) > julianday(?2))"
    );
    let row = connection
        .query_row(&sql, params![decision_id, now], policy_row_to_json)
        .optional()?;
    let Some(row) = row else { return Ok(false) };
    let source = row.get("source").and_then(Value::as_str).unwrap_or("");
    if NON_REUSABLE_REMOTE_SOURCES.contains(&source) {
        return Ok(false);
    }
    if source == "policy-bundle" {
        let Some(identities) = evidence.policy_bundle_identities else {
            return Ok(false);
        };
        let identity = materialized_policy_bundle_row_identity(&row);
        if !identities
            .iter()
            .any(|candidate| Value::from(candidate.clone()) == identity)
        {
            return Ok(false);
        }
    }
    let (integrity, state) = row_integrity(&row, source, evidence);
    if integrity.status != "valid" {
        return Ok(false);
    }
    let current = policy_row_payload(&row, Some(&integrity), state.as_ref());
    if IDENTITY_KEYS
        .iter()
        .any(|key| row_value(&current, key) != row_value(decision, key))
    {
        return Ok(false);
    }
    if disposition == "consumed" {
        let deleted = connection.execute(
            "delete from policy_decisions where decision_id = ?1 and action = 'allow'",
            params![decision_id],
        )?;
        if deleted != 1 {
            return Ok(false);
        }
    }
    insert_event(
        connection,
        "approval.policy_reuse_applied",
        &json!({
            "decision_id": decision_id,
            "harness": row_value(&current, "harness"),
            "artifact_id": row_value(&current, "artifact_id"),
            "scope": row_value(&current, "scope"),
        }),
        now,
    )?;
    Ok(true)
}

/// One validated member of the batch and its claim disposition.
pub type Member<'a> = (&'a Value, &'static str);

fn claim_members(
    connection: &Connection,
    members: &[Member<'_>],
    expected_revision: i64,
    now: &str,
    evidence: &ClaimEvidence<'_>,
    bound: &dyn Fn(&Connection, &[Member<'_>]) -> rusqlite::Result<bool>,
) -> rusqlite::Result<bool> {
    if approval_authority_revision(connection)? != expected_revision {
        return Ok(false);
    }
    // The caller gathered `evidence` before this lock was taken: refuse the
    // batch unless the sources it came from are unchanged under the lock.
    if !bound(connection, members)? {
        return Ok(false);
    }
    for (decision, disposition) in members {
        let claimed = if let Some(approval_id) = text_non_empty(decision, "approval_id") {
            claim_local_once_member(
                connection,
                decision,
                approval_id,
                disposition,
                now,
                evidence,
            )?
        } else if let Some(decision_id) = integer_id(decision, "decision_id") {
            claim_policy_member(
                connection,
                decision,
                decision_id,
                disposition,
                now,
                evidence,
            )?
        } else {
            false
        };
        if !claimed {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Claim a batch of saved allows atomically. `Ok(false)` means the decision
/// expired, changed, was consumed elsewhere, was not a claimable allow, or its
/// evidence no longer matched the store (`bound`, run under the write lock); a
/// store failure is an `Err` and never a claim.
pub fn claim_approval_reuse_decisions(
    connection: &Connection,
    decisions: &[Value],
    now: &str,
    evidence: &ClaimEvidence<'_>,
    bound: &dyn Fn(&Connection, &[Member<'_>]) -> rusqlite::Result<bool>,
) -> rusqlite::Result<bool> {
    let Ok((unique, expected_revision)) = unique_members(decisions) else {
        return Ok(false);
    };
    if unique.is_empty() {
        return Ok(true);
    }
    let mut members: Vec<Member<'_>> = Vec::with_capacity(unique.len());
    for decision in unique {
        let Some(disposition) = approval_reuse_claim_disposition(decision) else {
            return Ok(false);
        };
        members.push((decision, disposition));
    }
    connection.execute_batch("BEGIN IMMEDIATE")?;
    match claim_members(
        connection,
        &members,
        expected_revision,
        now,
        evidence,
        bound,
    ) {
        Ok(true) => {
            connection.execute_batch("COMMIT")?;
            Ok(true)
        }
        Ok(false) => {
            connection.execute_batch("ROLLBACK")?;
            Ok(false)
        }
        Err(error) => {
            let _ = connection.execute_batch("ROLLBACK");
            Err(error)
        }
    }
}
