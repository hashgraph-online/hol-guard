//! Claim a relayed call's saved allow or one-shot approval, then decide it.
//!
//! `_allow_and_forward` (`runtime_mcp.py`) claims the pending saved approval
//! of an allowed call before forwarding it:
//!
//! 1. it drains the child stream and re-checks the catalog authority, and
//!    answers a changed catalog without claiming (2549-2568). The relay does
//!    this itself before it asks for the claim; a ticket it never sends
//!    expires here unspent;
//! 2. it claims the row with `claim_approval_reuse_decisions((pending,))`
//!    (2570), whose evidence `_claim_integrity_evidence` procures
//!    (`store_policy.py` 1386-1428);
//! 3. it re-resolves the call (2585-2606) and asks `tool_postclaim` whether
//!    the claimed authority still covers it (2608-2644);
//! 4. it forwards with the fresh identity and the post-claim evidence, or
//!    answers a stored block or a terminal action (2646-2690).
//!
//! The resident runs steps 2 to 4 in one write transaction and commits the
//! claim only once it has an answer the relay can give as the proxy would:
//! a forward, a stored block, a terminal block or a post-claim re-approval
//! queue (2674-2684), with its evidence queued or held. Every other outcome
//! rolls the claim back and defers, so the call is answered "no native
//! decision" with the approval unspent: a declined claim (which the proxy
//! queues for re-approval, 2570-2582), a package intent the fresh resolve now
//! finds (which the proxy sends through its package policy), and any lane,
//! store, policy or evidence failure.
//!
//! A post-claim re-approval spends the claim, as the proxy's does, and then
//! answers by the bound blocked-request mode. The safe-alternative block is
//! settled inside the transaction. The `ask` request is checked and shaped
//! there too, but written only once the claim commits: its store write takes
//! the storage gate and a connection of its own, which must not wait on the
//! claim's write lock. A write that then fails defers with the approval
//! spent, where the proxy raises; the retried call no longer finds the spent
//! approval and queues through the decision's own route.
//!
//! Declared divergences from the proxy:
//!
//! - the claim evidence is the integrity state and key the daemon published,
//!   which the store must still hold under the write lock, not a fresh
//!   keyring refresh;
//! - the proxy refreshes its config after the claim (2585); the resident
//!   instead requires the lane admission (snapshot and binding) to be the
//!   very one the decision was made under, and defers on any change before
//!   claiming, so the fresh resolve reads the same config;
//! - the write lock waits `CLAIM_BUSY` rather than five seconds, and a claim
//!   that would commit after `CLAIM_BUDGET` rolls back, so it commits well
//!   inside the relay's wait; a reply lost after the commit still leaves the
//!   approval spent with the call answered "no native decision";
//! - a policy-bundle row, whose identities the resident does not derive,
//!   defers. The decision lookup never selects one, since the relay gives it
//!   no bundle identities, so this only guards the claim itself.

use super::store::{self, STORE_UNREADABLE};
use super::{
    admit, ask, encode, queue, resolve, settle, Answer, ClaimContext, Claimed, Resolved, Routed,
    ASK_MODE, IDENTITY_FAILED,
};
use crate::approval_proof_op::{
    fresh_tool_approval, lookup_preserves_claim, postclaim_review_authorized, Disposition,
};
use crate::claim_reuse::{claim_approval_reuse_decisions_then, ClaimEvidence};
use crate::claim_reuse_binding::evidence_is_bound;
use crate::local_store_read::{schema_version, STORE_FILE_NAME, SUPPORTED_SCHEMA_VERSION};
use crate::mcp_relay_claims::McpRelayClaimRequestV1;
use crate::policy_store::PolicySnapshotStore;
use guard_contracts::{ClaimEvidenceBindingV1, McpToolPostclaimQueryV1};
use guard_policy_snapshot::policy_integrity::is_remote_policy_source;
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the claim waits for the store's write lock.
const CLAIM_BUSY: Duration = Duration::from_millis(500);
/// A claim not ready to commit by then rolls back: the relay waits longer.
pub(crate) const CLAIM_BUDGET: Duration = Duration::from_millis(1_500);

const CLAIM_UNKNOWN: &str = "mcp_relay_claim_unknown";
const CLAIM_AUTHORITY_CHANGED: &str = "mcp_relay_claim_authority_changed";
const CLAIM_BUNDLE: &str = "mcp_relay_claim_policy_bundle";
const CLAIM_DECLINED: &str = "mcp_relay_claim_declined";
const CLAIM_STORE: &str = "mcp_relay_claim_store_failed";
const CLAIM_LATE: &str = "mcp_relay_claim_late";
const POSTCLAIM_FAILED: &str = "mcp_relay_postclaim_failed";

/// Spend one held claim and answer the call.
pub(crate) fn claim(
    request: &McpRelayClaimRequestV1,
    policy_store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    let started = Instant::now();
    let answer = policy_store
        .mcp_relay_claims()
        .take(&request.ticket, started)
        .ok_or(CLAIM_UNKNOWN)
        .and_then(|context| spend(request, &context, policy_store, started));
    encode(answer)
}

fn spend(
    request: &McpRelayClaimRequestV1,
    context: &ClaimContext,
    policy_store: &PolicySnapshotStore,
    started: Instant,
) -> Result<Answer, &'static str> {
    if request.guard_home != context.request.guard_home {
        return Err(CLAIM_UNKNOWN);
    }
    // The lane admission must be the one the decision was made under: any
    // republished snapshot or binding (config, integrity state or key) defers
    // before anything is claimed.
    let admitted = admit(&context.request, policy_store)?;
    let held = &context.admitted;
    if !unchanged(
        (&held.workspace, &held.snapshot, &held.binding),
        (&admitted.workspace, &admitted.snapshot, &admitted.binding),
    ) {
        return Err(CLAIM_AUTHORITY_CHANGED);
    }
    let (state, key) = store::published_integrity(&admitted.binding)?;
    let pending = &context.claimed.pending;
    // `_claim_integrity_evidence` for the one pending row.
    let source = pending.get("source").and_then(Value::as_str);
    if source == Some("policy-bundle") {
        return Err(CLAIM_BUNDLE);
    }
    let local_once = pending
        .get("approval_id")
        .and_then(Value::as_str)
        .is_some_and(|id| !id.is_empty());
    let policy = !local_once && source.is_some() && !is_remote_policy_source(source);
    let key_bytes: &[u8] = &key.key;
    let evidence = ClaimEvidence {
        integrity_state: policy.then_some(&state),
        integrity_key: policy.then_some(key_bytes),
        integrity_key_id: policy.then_some(key.key_id.as_str()),
        local_once_key: local_once.then_some(key_bytes),
        local_once_key_id: local_once.then_some(key.key_id.as_str()),
        policy_bundle_identities: None,
    };
    // `claim_evidence_binding(connection, bundle=False)`.
    let binding = ClaimEvidenceBindingV1::default();
    let connection = open_for_claim(&request.guard_home)?;
    let now = store::utc_now().ok_or(CLAIM_STORE)?;
    let decisions = [Value::Object(pending.clone())];
    let mut refused = None;
    let claimed = claim_approval_reuse_decisions_then(
        &connection,
        &decisions,
        &now,
        &evidence,
        &|connection, members| evidence_is_bound(connection, members, &evidence, Some(&binding)),
        false,
        &mut |connection| match after_claim(connection, context, policy_store, started) {
            Ok(answer) => Ok(Some(answer)),
            Err(reason) => {
                refused = Some(reason);
                Ok(None)
            }
        },
    );
    match claimed {
        Ok(Some(Spent::Answer(answer))) => Ok(answer),
        Ok(Some(Spent::Ask(requeue))) => {
            let Requeue {
                fresh,
                prepared,
                append,
            } = *requeue;
            let routed = prepared.write(&context.request)?;
            settle(&context.request, &fresh, routed, Some(append), policy_store)
        }
        Ok(None) => Err(refused.unwrap_or(CLAIM_DECLINED)),
        Err(_) => Err(CLAIM_STORE),
    }
}

/// What a committed claim answers with.
enum Spent {
    /// An answer settled inside the claim's transaction.
    Answer(Answer),
    /// A re-approval request to write once the claim commits.
    Ask(Box<Requeue>),
}

/// The fresh call and the re-approval request a committed claim writes.
struct Requeue {
    fresh: Resolved,
    prepared: ask::Prepared,
    append: Vec<Value>,
}

/// Whether a lane admission is the very one a decision was made under: the
/// same workspace and the same published snapshot and binding, not merely
/// equal ones, so any republish in between counts as a change.
fn unchanged<S, B>(held: (&str, &Arc<S>, &Arc<B>), now: (&str, &Arc<S>, &Arc<B>)) -> bool {
    held.0 == now.0 && Arc::ptr_eq(held.1, now.1) && Arc::ptr_eq(held.2, now.2)
}

/// The store, writable, at a schema the resident reads.
fn open_for_claim(guard_home: &str) -> Result<Connection, &'static str> {
    let connection = Connection::open_with_flags(
        Path::new(guard_home).join(STORE_FILE_NAME),
        OpenFlags::SQLITE_OPEN_READ_WRITE,
    )
    .map_err(|_| STORE_UNREADABLE)?;
    connection
        .busy_timeout(CLAIM_BUSY)
        .map_err(|_| STORE_UNREADABLE)?;
    match schema_version(&connection).map_err(|_| STORE_UNREADABLE)? {
        Some(version) if version <= SUPPORTED_SCHEMA_VERSION => Ok(connection),
        _ => Err(STORE_UNREADABLE),
    }
}

/// Steps 3 and 4 on the claimed store, inside the claim's transaction: the
/// answer to commit with, or why the claim rolls back.
fn after_claim(
    connection: &Connection,
    context: &ClaimContext,
    policy_store: &PolicySnapshotStore,
    started: Instant,
) -> Result<Spent, &'static str> {
    // The fresh resolve only reads, as on the decision's read-only snapshot.
    connection
        .execute_batch("PRAGMA query_only = ON")
        .map_err(|_| STORE_UNREADABLE)?;
    let fresh = resolve(&context.request, &context.admitted, Some(connection));
    connection
        .execute_batch("PRAGMA query_only = OFF")
        .map_err(|_| STORE_UNREADABLE)?;
    let fresh = fresh?;
    let (routed, append) = postclaim(&context.claimed, &fresh)?;
    let routed = match routed {
        // `_queue_approval_center_response`, straight to the queue: the
        // proxy raises no native prompt or inline elicitation here.
        Routed::Queue { policy_action } => {
            let mode = context
                .admitted
                .binding
                .review
                .blocked_request_mode
                .as_deref();
            if mode == Some(ASK_MODE) {
                let prepared = ask::prepare(
                    &context.request,
                    &context.admitted,
                    &fresh,
                    policy_action,
                    &append,
                )?;
                if started.elapsed() >= CLAIM_BUDGET {
                    return Err(CLAIM_LATE);
                }
                return Ok(Spent::Ask(Box::new(Requeue {
                    fresh,
                    prepared,
                    append,
                })));
            }
            queue::safe_alternative(mode, fresh.redaction_level.as_deref(), policy_action)?
        }
        routed => routed,
    };
    if started.elapsed() >= CLAIM_BUDGET {
        return Err(CLAIM_LATE);
    }
    settle(&context.request, &fresh, routed, Some(append), policy_store).map(Spent::Answer)
}

/// `tool_postclaim` for the fresh decision (2608-2690), as a route.
fn postclaim(claimed: &Claimed, fresh: &Resolved) -> Result<(Routed, Vec<Value>), &'static str> {
    let artifact = &fresh.identity.artifact;
    let artifact_hash = fresh
        .identity
        .artifact_hash
        .clone()
        .ok_or(IDENTITY_FAILED)?;
    let mut query = McpToolPostclaimQueryV1 {
        fresh: crate::mcp_tool_policy_proxy::facts(&fresh.decision),
        artifact_id: artifact.artifact_id.clone(),
        expected_artifact_id: claimed.artifact_id.clone(),
        artifact_hash: artifact_hash.clone(),
        expected_artifact_hash: claimed.artifact_hash.clone(),
        claim_authorizes_review: postclaim_review_authorized(
            claimed.disposition,
            Some(&claimed.pending),
            fresh.decision.pending.as_ref(),
        ),
        fresh_claim_allows_reapproval: None,
    };
    let mut reply = crate::mcp_proxy_postclaim::tool_postclaim(&query);
    if reply["need"].as_str() == Some("fresh_claim_allows_reapproval") {
        query.fresh_claim_allows_reapproval = Some(
            claimed.disposition == Some(Disposition::Consumed)
                && lookup_preserves_claim(fresh.decision.approval_reuse_reason_code.as_deref())
                && fresh_tool_approval(
                    Some(&claimed.pending),
                    &artifact.harness,
                    &artifact.artifact_id,
                    &artifact_hash,
                ),
        );
        reply = crate::mcp_proxy_postclaim::tool_postclaim(&query);
    }
    if !reply["need"].is_null() {
        return Err(POSTCLAIM_FAILED);
    }
    let append = reply["evidence_append"]
        .as_array()
        .cloned()
        .ok_or(POSTCLAIM_FAILED)?;
    let disposition = &reply["disposition"];
    let routed = match disposition["kind"].as_str() {
        Some("forward") => Routed::Forward {
            source: claimed.source.clone(),
            policy_action: claimed.policy_action.clone(),
            // A claimed saved approval is already saved policy.
            remember: false,
        },
        Some("stored_block") => Routed::StoredBlock,
        Some("terminal") => Routed::Terminal {
            policy_action: disposition["policy_action"]
                .as_str()
                .ok_or(POSTCLAIM_FAILED)?
                .to_owned(),
        },
        Some("queue_reapproval") => Routed::Queue {
            policy_action: disposition["policy_action"]
                .as_str()
                .ok_or(POSTCLAIM_FAILED)?
                .to_owned(),
        },
        _ => return Err(POSTCLAIM_FAILED),
    };
    Ok((routed, append))
}

#[cfg(test)]
#[path = "mcp_relay_decide_claim_tests.rs"]
mod tests;
