//! Claim a relayed package call's saved approvals, then decide it.
//!
//! The package lane's forward is the one route whose policies may each have
//! left a saved approval pending, and the proxy spends both before it
//! forwards (`_handle_package_request`'s claim branch,
//! `runtime_mcp.py:1660`). This is the package lane's counterpart to
//! `mcp_relay_decide_claim.rs`, and it runs the same transaction: claim the
//! rows, re-read both authorities on the claimed store, ask whether the
//! claimed authority still covers what would run now, and commit only once
//! there is an answer the relay can give as the proxy would. Every other
//! outcome rolls the claim back and defers, so the call is answered "no
//! native decision" with the approvals unspent.
//!
//! Two things differ from the tool lane's claim, both because of what a
//! package call is:
//!
//! * the re-read is two resolutions, not one. The tool authority is resolved
//!   as any claimed call's is, and the package policy is re-resolved beside
//!   it from the evaluation the relay re-read the request with after the
//!   claim (`mcp_relay_decide_package_leg.rs`). A claimed call takes no lane
//!   route — the lane would compose the same forward and raise the very claim
//!   this call is spending — so the route comes from the post-claim
//!   revalidation instead (`mcp_relay_decide_package_postclaim.rs`);
//! * the call the gate no longer reads as a package request defers, which is
//!   the mirror of the tool claim's own refusal. A claim is held for the lane
//!   that held it, and neither lane answers the other's call.
//!
//! A queued half is written once the claim commits, for the same reason the
//! tool claim's is: its store write takes the storage gate and a connection
//! of its own, which must not wait on the claim's write lock. That holds for
//! both shapes of queue here — the package-shaped approval row the bound
//! `ask` mode writes, and the approval-center row a queued tool leg writes.

use super::claim::{integrity_evidence, open_for_claim, unchanged, CLAIM_BUDGET};
use super::package_claim::{self, Settled};
use super::package_route::ToolLeg;
use super::store::{self, STORE_UNREADABLE};
use super::{
    admit, ask, package, package_lane, package_leg, package_postclaim, queue, settle,
    settle_package, Answer, HeldClaim, Legged, PackageClaimContext, PackageLeg, Resolved, Routed,
    ASK_MODE, EVIDENCE_FULL,
};
use crate::claim_reuse::claim_approval_reuse_decisions_then;
use crate::claim_reuse_binding::evidence_is_bound;
use crate::mcp_relay_claims::McpRelayClaimRequestV1;
use crate::policy_store::PolicySnapshotStore;
use guard_command::package_intent_common::PackageIntent;
use guard_contracts::ClaimEvidenceBindingV1;
use rusqlite::Connection;
use serde_json::{Map, Value};
use std::time::Instant;

/// The claim names a package call this resident is not holding.
const PACKAGE_CLAIM_UNKNOWN: &str = "mcp_relay_package_claim_unknown";
/// The lane admission is no longer the one the decision was made under.
const PACKAGE_CLAIM_AUTHORITY_CHANGED: &str = "mcp_relay_package_claim_authority_changed";
/// The gate no longer reads the claimed call as a package request.
const PACKAGE_CLAIM_INTENT_LOST: &str = "mcp_relay_package_claim_intent_lost";
/// Neither policy left a row, so there is nothing for this claim to spend.
const PACKAGE_CLAIM_EMPTY: &str = "mcp_relay_package_claim_empty";
/// The store declined the claim, which the proxy queues for re-approval.
const PACKAGE_CLAIM_DECLINED: &str = "mcp_relay_package_claim_declined";
const PACKAGE_CLAIM_STORE: &str = "mcp_relay_package_claim_store_failed";
/// A claim not ready to commit inside the relay's wait rolls back.
const PACKAGE_CLAIM_LATE: &str = "mcp_relay_package_claim_late";
/// The re-resolution did not produce the claimed call's package policy.
const PACKAGE_CLAIM_RERESOLVE: &str = "mcp_relay_package_claim_reresolve_failed";

/// Spend one held package claim and answer the call.
pub(super) fn spend_package(
    request: &McpRelayClaimRequestV1,
    context: PackageClaimContext,
    policy_store: &PolicySnapshotStore,
    started: Instant,
) -> Result<Answer, &'static str> {
    if request.guard_home != context.request.guard_home {
        return Err(PACKAGE_CLAIM_UNKNOWN);
    }
    // The policy this claim is spent against is resolved from the post-claim
    // evaluation, whose archive and registry rounds the relay performs with
    // the external archive network authorized (`runtime_mcp.py:1832`). No
    // round trip can hold them, so the rows are held again and the relay
    // sends the same claim back with the evaluation attached. Nothing is
    // claimed and nothing is written until it does.
    let Some(evaluation) = request.package_evaluation.as_ref() else {
        return policy_store
            .mcp_relay_claims()
            .hold(HeldClaim::Package(context), Instant::now())
            .map(|ticket| Answer::Evaluate {
                ticket: Some(ticket),
            })
            .ok_or(EVIDENCE_FULL);
    };
    let context = &context;
    // The lane admission must be the one the decision was made under: any
    // republished snapshot or binding defers before anything is claimed.
    let admitted = admit(&context.request, policy_store)?;
    let held = &context.admitted;
    if !unchanged(
        (&held.workspace, &held.snapshot, &held.binding),
        (&admitted.workspace, &admitted.snapshot, &admitted.binding),
    ) {
        return Err(PACKAGE_CLAIM_AUTHORITY_CHANGED);
    }
    let rows = package_claim::rows(&context.claimed);
    if rows.is_empty() {
        return Err(PACKAGE_CLAIM_EMPTY);
    }
    let (state, key) = store::published_integrity(&admitted.binding)?;
    let evidence = integrity_evidence(&rows, &state, key)?;
    // `claim_evidence_binding(connection, bundle=False)`.
    let binding = ClaimEvidenceBindingV1::default();
    let connection = open_for_claim(&request.guard_home)?;
    let now = store::utc_now().ok_or(PACKAGE_CLAIM_STORE)?;
    let decisions: Vec<Value> = rows
        .iter()
        .map(|row| Value::Object((*row).clone()))
        .collect();
    let mut refused = None;
    let claimed = claim_approval_reuse_decisions_then(
        &connection,
        &decisions,
        &now,
        &evidence,
        &|connection, members| evidence_is_bound(connection, members, &evidence, Some(&binding)),
        false,
        &mut |connection| match after_claim(connection, context, evaluation, policy_store, started)
        {
            Ok(spent) => Ok(Some(spent)),
            Err(reason) => {
                refused = Some(reason);
                Ok(None)
            }
        },
    );
    match claimed {
        Ok(Some(Spent::Answer(answer))) => Ok(answer),
        Ok(Some(Spent::Queued(queued))) => {
            let Queued { fresh, write } = *queued;
            match write {
                // `settle_package` writes the package-shaped approval row the
                // bound `ask` mode answers a queued request with.
                Write::Package(packaged) => settle_package(
                    &context.request,
                    &context.admitted,
                    &fresh,
                    &packaged,
                    policy_store,
                ),
                Write::Tool { prepared, append } => {
                    let routed = prepared.write(&context.request)?;
                    settle(&context.request, &fresh, routed, Some(append), policy_store)
                }
            }
        }
        Ok(None) => Err(refused.unwrap_or(PACKAGE_CLAIM_DECLINED)),
        Err(_) => Err(PACKAGE_CLAIM_STORE),
    }
}

/// What a committed package claim answers with.
enum Spent {
    /// An answer settled inside the claim's transaction.
    Answer(Answer),
    /// A queued request to write once the claim commits.
    Queued(Box<Queued>),
}

/// The fresh call and the row a committed claim writes for it.
struct Queued {
    fresh: Resolved,
    write: Write,
}

/// Which queue a committed claim writes: the package lane's own row, or the
/// approval-center row a queued tool leg takes.
enum Write {
    Package(Box<package_leg::Packaged>),
    Tool {
        prepared: ask::Prepared,
        append: Vec<Value>,
    },
}

/// The re-read and the post-claim route, on the claimed store and inside the
/// claim's transaction: the answer to commit with, or why the claim rolls
/// back.
fn after_claim(
    connection: &Connection,
    context: &PackageClaimContext,
    evaluation: &Map<String, Value>,
    policy_store: &PolicySnapshotStore,
    started: Instant,
) -> Result<Spent, &'static str> {
    // A package claim is held for a call the gate read a package request in,
    // so a call it no longer does rolls the claim back rather than answering
    // it off the tool policy alone.
    let intent = package::package_gate(&context.request)?.ok_or(PACKAGE_CLAIM_INTENT_LOST)?;
    // Both re-reads only read, as on the decision's read-only snapshot.
    connection
        .execute_batch("PRAGMA query_only = ON")
        .map_err(|_| STORE_UNREADABLE)?;
    let reread = resolve_claimed(connection, context, &intent, evaluation);
    connection
        .execute_batch("PRAGMA query_only = OFF")
        .map_err(|_| STORE_UNREADABLE)?;
    let (fresh, reresolved) = reread?;
    let package_leg::Reresolved {
        artifact,
        workspace,
        policy,
    } = reresolved;
    let postclaimed = package_postclaim::postclaim(
        &fresh.decision,
        package_claim::tool_context(&context.claimed, &fresh)?,
        // The package request the gate still reads resolves to the artifact
        // just rebuilt from it.
        true,
        || package_claim::package_facts(&context.claimed, &artifact, &policy, &fresh.decision),
    )?;
    let queue_binding = package_lane::QueueBinding {
        blocked_request_mode: context
            .admitted
            .binding
            .review
            .blocked_request_mode
            .as_deref(),
        redaction_level: fresh.redaction_level.as_deref(),
    };
    let settled = package_claim::settled(
        postclaimed,
        &context.request.build.tool_name,
        &context.request.build.server_name,
        &policy,
        artifact,
        &workspace,
        queue_binding,
    )?;
    match settled {
        Settled::Package(packaged) => {
            if matches!(
                packaged.outcome,
                package_lane::PackageOutcome::AskPackage(_)
            ) {
                return queued(started, fresh, Write::Package(packaged));
            }
            spend_budget(started)?;
            settle_package(
                &context.request,
                &context.admitted,
                &fresh,
                &packaged,
                policy_store,
            )
            .map(Spent::Answer)
        }
        Settled::Tool { leg, append } => {
            let routed = match leg {
                ToolLeg::StoredBlock => Routed::StoredBlock {
                    package_request: true,
                },
                ToolLeg::Terminal { policy_action } => Routed::Terminal { policy_action },
                // `_queue_approval_center_response`, straight to the queue:
                // the proxy raises no native prompt or inline elicitation for
                // a claimed call.
                ToolLeg::Queue { policy_action } => {
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
                        return queued(started, fresh, Write::Tool { prepared, append });
                    }
                    queue::safe_alternative(mode, fresh.redaction_level.as_deref(), policy_action)?
                }
            };
            spend_budget(started)?;
            settle(&context.request, &fresh, routed, Some(append), policy_store).map(Spent::Answer)
        }
    }
}

/// Re-read both authorities of the claimed call on the claimed store: the
/// tool authority as any claimed call's, and the package policy beside it
/// from the post-claim evaluation.
fn resolve_claimed(
    connection: &Connection,
    context: &PackageClaimContext,
    intent: &PackageIntent,
    evaluation: &Map<String, Value>,
) -> Result<(Resolved, package_leg::Reresolved), &'static str> {
    let (fresh, legged) = super::resolve(
        &context.request,
        &context.admitted,
        Some(connection),
        Some(PackageLeg::Claimed(intent, evaluation)),
    )?;
    let reresolved = legged
        .and_then(Legged::reresolved)
        .ok_or(PACKAGE_CLAIM_RERESOLVE)?;
    Ok((fresh, reresolved))
}

/// Hold a queued answer for the commit to write, if the claim still commits
/// inside the relay's wait.
fn queued(started: Instant, fresh: Resolved, write: Write) -> Result<Spent, &'static str> {
    spend_budget(started)?;
    Ok(Spent::Queued(Box::new(Queued { fresh, write })))
}

/// A claim that would commit after the budget rolls back: the relay waits
/// longer than the resident is willing to hold the store's write lock.
fn spend_budget(started: Instant) -> Result<(), &'static str> {
    if started.elapsed() >= CLAIM_BUDGET {
        return Err(PACKAGE_CLAIM_LATE);
    }
    Ok(())
}
