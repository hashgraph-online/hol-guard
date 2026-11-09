//! Guard Cloud exact-command Allow rules at the hook edge.
//!
//! A rule made from an approval in Guard Cloud ("Allow this exact command")
//! reaches the device as an artifact-scoped `allow` row under the command's
//! exact-command id, written from the signed policy bundle. Native review
//! never read those rows: the edge applied a Cloud block or review on the
//! exact command ([`crate::edge_exact_command_review`]) but not an allow, and
//! the saved-decision step reuses only an approval-gate allow bound to the
//! exact-action token. The command the policy allowed was still held for a
//! person.
//!
//! The edge now settles such a review at allow, within the limits a user's
//! explicit extension Allow has (`OVERRIDABLE_NATIVE_REASONS`,
//! `native_command_controls_precedence.rs`):
//!
//! - only a review of a bounded shell action that touches no sensitive
//!   target, held for one of the native shape judgments an explicit Allow may
//!   settle; a block, a sandbox requirement, a require-reapproval and every
//!   other review reason stay as they are;
//! - only a rule that names the command as the hook received it. A block or
//!   review rule matches every spelling of a command, but an allow lifts only
//!   the text it was approved for;
//! - only while the cached signed bundle still yields the row, checked the
//!   way the policy lookup keeps a `policy-bundle` row. A v2 bundle's
//!   `policy-bundle-canonical` row is checked against the rules that bundle
//!   compiles to for this device. A row the bundle no longer authorizes, or a
//!   bundle Guard cannot validate, lifts nothing.
//!
//! The caller applies block and review rules first, in the same read
//! snapshot, so a block or review on any spelling of the command wins over
//! this allow even while a policy sync commits.

use guard_contracts::PreToolResultV1;
use rusqlite::{params, Connection};
use serde_json::{json, Value};

use crate::local_store_read::table_exists;
use crate::policy_bundle_store_identities::{
    cached_bundle_authority, canonical_identities, Identity,
};
use crate::policy_decision_lookup_op::materialized_policy_bundle_row_identity;

const POLICY_ALLOW: &str = "policy_exact_command_allow";
const POLICY_ALLOW_REASON: &str = "Your Guard Cloud policy allows this exact command.";
/// The native judgments of a command's shape that a user's explicit Allow may
/// settle (`OVERRIDABLE_NATIVE_REASONS`).
const LIFTABLE_REASONS: &[&str] = &[
    "native_command_review_required",
    "native_destructive_command",
    "native_network_review",
    "native_package_review",
    "native_process_service_review",
    "native_process_service_dangerous",
];

/// The decision identities the signed bundle authorizes at `now`, or `None`
/// when they cannot be derived.
pub(crate) type BundleIdentities = fn(&Connection, &str) -> Option<Vec<Identity>>;

/// The identities the cached signed policy bundle yields for this device: a
/// v1 bundle's materialized decisions, and the rules a canonical (v2) bundle
/// compiles to.
pub(crate) fn cached_identities(connection: &Connection, now: &str) -> Option<Vec<Identity>> {
    let (mut identities, bundle) = cached_bundle_authority(connection, now)?;
    if let Some(bundle) = bundle {
        identities.extend(canonical_identities(connection, &bundle)?);
    }
    Some(identities)
}

/// Settles a liftable review at allow when a Guard Cloud policy rule allows
/// one of `commands` exactly; any other result, or any read that fails, is
/// returned unchanged. `connection` is the read snapshot the caller matched
/// the block and review rules in.
pub(crate) fn apply(
    connection: &Connection,
    commands: &[&str],
    now_micros: Option<i64>,
    result: PreToolResultV1,
    identities: BundleIdentities,
) -> PreToolResultV1 {
    if !liftable(&result) {
        return result;
    }
    let Some(now) = now_micros
        .and_then(|now| crate::policy_bundle_time::micros_to_utc_isoformat(now, "+00:00"))
    else {
        return result;
    };
    let harness = result.action.harness.as_str();
    if allowed(connection, harness, commands, now_micros, &now, identities) {
        settle(result)
    } else {
        result
    }
}

/// A review a user's explicit Allow could settle.
fn liftable(result: &PreToolResultV1) -> bool {
    result.minimum_action == "review"
        && result.policy_action == "review"
        && result.action.bounded
        && !result.action.sensitive_target
        && LIFTABLE_REASONS.contains(&result.reason_code.as_str())
}

/// Whether a live signed-bundle allow row (`policy-bundle` or
/// `policy-bundle-canonical`) names one of `commands` exactly and the signed
/// bundle still yields it.
fn allowed(
    connection: &Connection,
    harness: &str,
    commands: &[&str],
    now_micros: Option<i64>,
    now: &str,
    identities: BundleIdentities,
) -> bool {
    if !table_exists(connection, "policy_decisions").unwrap_or(false) {
        return false;
    }
    let mut rows = Vec::new();
    for command in commands {
        let candidates = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
            command: Some(command),
            artifact_type: Some("shell_command"),
            artifact_id: None,
            artifact_name: None,
            harness: None,
        });
        for id in &candidates.exact_artifact_ids {
            match allow_rows(connection, harness, id) {
                Ok(found) => rows.extend(found),
                Err(_) => return false,
            }
        }
    }
    let live: Vec<Value> = rows
        .into_iter()
        .filter(|row| {
            !crate::edge_exact_command_review::expired(
                row.get("expires_at").and_then(Value::as_str),
                now_micros,
            )
        })
        .collect();
    if live.is_empty() {
        return false;
    }
    // Derived last, so a call no allow row names never pays for the bundle's
    // signature checks.
    let Some(authorized) = identities(connection, now) else {
        return false;
    };
    live.iter().any(|row| {
        let identity = materialized_policy_bundle_row_identity(row);
        authorized
            .iter()
            .any(|authorized| Value::from(authorized.clone()) == identity)
    })
}

/// The artifact-scoped signed-bundle allow rows saved under `id` for
/// `harness` or every harness, with the columns their identity is read from.
fn allow_rows(connection: &Connection, harness: &str, id: &str) -> rusqlite::Result<Vec<Value>> {
    let mut statement = connection.prepare_cached(
        "select harness, scope, artifact_id, artifact_hash, workspace, publisher, action, \
         reason, owner, source, expires_at from policy_decisions \
         where harness in (?1, '*') and artifact_id = ?2 and scope = 'artifact' \
         and action = 'allow' and source in ('policy-bundle', 'policy-bundle-canonical')",
    )?;
    let rows = statement.query_map(params![harness, id], |row| {
        let text = |index: usize| row.get::<_, Option<String>>(index);
        Ok(json!({
            "harness": text(0)?,
            "scope": text(1)?,
            "artifact_id": text(2)?,
            "artifact_hash": text(3)?,
            "workspace": text(4)?,
            "publisher": text(5)?,
            "action": text(6)?,
            "reason": text(7)?,
            "owner": text(8)?,
            "source": text(9)?,
            "expires_at": text(10)?,
        }))
    })?;
    rows.collect()
}

fn settle(mut result: PreToolResultV1) -> PreToolResultV1 {
    result.policy_action = "allow".into();
    result.minimum_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = POLICY_ALLOW.into();
    result.reason = POLICY_ALLOW_REASON.into();
    result
}

#[cfg(test)]
#[path = "edge_exact_command_allow_tests.rs"]
mod tests;
