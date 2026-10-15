//! Durable local reservations, not actor verification or execution permission.
//! This module has no RPC and no provider caller; budget-bearing actions remain blocked.
use super::super::super::PolicySnapshotStore;
use super::super::super::{
    workspace_review_claim_index as replay, workspace_review_secure_state::WorkspaceReviewClaimV1,
};
use guard_command::business_input::PreparedBusinessInputV1;
use guard_contracts::{BusinessVolumeV1, MAX_BUSINESS_WIRE_COUNT};
use guard_policy_snapshot::business_budget::{BusinessBudgetScopeV1, BusinessBudgetV1};
use guard_policy_snapshot::{canonical_json_bytes, digest_bytes};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[path = "workspace_review_business_budget_anchor.rs"]
mod anchor;
const DIRECTORY: &str = "business-budget-ledger";
const MAX_BYTES: u64 = 4 * 1024 * 1024;
fn invalid() -> String {
    "native_business_budget_state_invalid".into()
}

// These bindings must come from the authenticated worker registry, never a
// tool payload. There is no registry-to-executor integration yet.
pub(super) struct ActorBindings {
    pub(super) user: Option<String>,
    pub(super) workflow: Option<String>,
}

// No Clone, Serialize or reload constructor. Progress cannot become a grant.
pub(super) struct Reservation {
    request_id: String,
    input_binding: String,
    ledger_root: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Event {
    request_id: String,
    input_binding: String,
    time_ms: u64,
    buckets: Vec<String>,
    volume: BusinessVolumeV1,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    schema: String,
    version: u16,
    events: Vec<Event>,
}

pub(super) fn reserve(
    store: &PolicySnapshotStore,
    request_id: &str,
    input: &PreparedBusinessInputV1,
    actor: &ActorBindings,
) -> Result<Reservation, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_millis();
    reserve_at(
        store,
        request_id,
        input,
        actor,
        u64::try_from(now).map_err(|_| invalid())?,
    )
}

fn reserve_at(
    store: &PolicySnapshotStore,
    request_id: &str,
    input: &PreparedBusinessInputV1,
    actor: &ActorBindings,
    time_ms: u64,
) -> Result<Reservation, String> {
    ensure_durable_platform()?;
    if time_ms == 0
        || !super::super::super::workspace_review_request::valid_request_id(request_id)
        || input.facts().require_complete_facts().is_err()
    {
        return Err(invalid());
    }
    super::super::super::approval_enrollment::with_transition_lock(store.state_base(), || {
        let snapshot = store.current_snapshot()?;
        if time_ms < snapshot.issued_at_ms || time_ms >= snapshot.expires_at_ms {
            return Err("native_business_budget_policy_expired".into());
        }
        let policy = snapshot.business_policy.as_ref().ok_or_else(invalid)?;
        policy.validate().map_err(|_| invalid())?;
        let budgets = policy.budgets.as_ref().ok_or_else(invalid)?;
        let mut matched = Vec::new();
        for budget in budgets {
            if budget
                .selector
                .matches(input.facts())
                .map_err(|_| invalid())?
            {
                matched.push((bucket(budget, input, actor)?, budget));
            }
        }
        if matched.is_empty() {
            return Err("native_business_budget_no_matching_declaration".into());
        }
        let (mut ledger, mut previous) = load(store.state_base())?;
        if previous
            .as_ref()
            .is_some_and(|anchor| time_ms < anchor.last_time_ms)
        {
            return Err("native_business_budget_clock_rollback".into());
        }
        let claim_id = request_digest(request_id);
        if previous
            .as_ref()
            .filter(|saved| saved.replay_index.claim_count > 0)
            .map(|saved| replay::find_claim(store.state_base(), &saved.replay_index, &claim_id))
            .transpose()?
            .flatten()
            .is_some()
        {
            return Err("native_business_budget_reservation_replay".into());
        }
        // Retain every event that could count under any supported window,
        // including after policy changes. Permanent replay history is separate.
        ledger.events.retain(|event| {
            time_ms.saturating_sub(event.time_ms)
                < guard_policy_snapshot::business_budget::BUSINESS_BUDGET_MAX_WINDOW_MS
        });
        for (key, budget) in &matched {
            ensure_capacity(&ledger, key, budget, time_ms, &input.facts().volume)?;
        }
        // Commit an authenticated empty starting point before creating any
        // immutable files. Orphans from a failed first reservation can then
        // be ignored without treating a missing anchor as empty history.
        if previous.is_none() {
            let empty_root = digest_bytes(&encode(&empty_ledger())?);
            anchor::store(
                store.state_base(),
                empty_root.clone(),
                time_ms,
                replay::ClaimIndexAnchor {
                    root: empty_root,
                    claim_count: 0,
                },
            )?;
            previous = anchor::load(store.state_base())?;
            if previous.is_none() {
                return Err(invalid());
            }
        }
        let mut buckets: Vec<_> = matched.into_iter().map(|(key, _)| key).collect();
        buckets.sort_unstable();
        buckets.dedup();
        ledger.events.push(Event {
            request_id: request_id.into(),
            input_binding: input.binding().into(),
            time_ms,
            buckets,
            volume: input.facts().volume.clone(),
        });
        let bytes = encode(&ledger)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("native_business_budget_storage_capacity".into());
        }
        let root_digest = digest_bytes(&bytes);
        let (path, private_root) = path(store.state_base(), &root_digest, true)?;
        if let Some((_, existing)) =
            super::super::super::policy_store_persistence::read_private_json(
                &path,
                MAX_BYTES,
                "business_budget",
                &private_root,
            )?
        {
            if existing != bytes {
                return Err(invalid());
            }
        } else {
            super::super::super::policy_store_persistence::persist_private_bytes(
                &path,
                &bytes,
                MAX_BYTES,
                "business_budget",
                &private_root,
            )?;
        }
        // All immutable ledger bytes are durable before the protected root
        // commits. A failure returns no reservation and never dispatches.
        let claim = budget_claim(request_id, input.binding());
        let replay_root = replay::insert_claim(
            store.state_base(),
            previous
                .as_ref()
                .filter(|saved| saved.replay_index.claim_count > 0)
                .map(|saved| saved.replay_index.root.as_str()),
            &claim,
        )?;
        replay::sync_directories_before_commit(store.state_base())?;
        let claim_count = previous
            .as_ref()
            .map_or(0, |saved| saved.replay_index.claim_count)
            .checked_add(1)
            .filter(|v| *v <= MAX_BUSINESS_WIRE_COUNT)
            .ok_or_else(invalid)?;
        anchor::store(
            store.state_base(),
            root_digest.clone(),
            time_ms,
            replay::ClaimIndexAnchor {
                root: replay_root,
                claim_count,
            },
        )?;
        if let Some(old) = previous
            .as_ref()
            .filter(|s| s.replay_index.claim_count > 0 && s.root != root_digest)
        {
            if let Ok((old_path, _)) = self::path(store.state_base(), &old.root, false) {
                let _ = std::fs::remove_file(old_path);
            }
        }
        Ok(Reservation {
            request_id: request_id.into(),
            input_binding: input.binding().into(),
            ledger_root: root_digest,
        })
    })
}

fn ensure_durable_platform() -> Result<(), String> {
    #[cfg(unix)]
    {
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err("native_business_budget_durability_unavailable".into())
    }
}

fn request_digest(request_id: &str) -> String {
    let mut bytes = b"guard.business-budget-request.v1\0".to_vec();
    bytes.extend_from_slice(request_id.as_bytes());
    digest_bytes(&bytes)
}
fn budget_claim(request_id: &str, input_binding: &str) -> WorkspaceReviewClaimV1 {
    let claim_id = request_digest(request_id);
    let mut bytes = b"guard.business-budget-reservation.v1\0".to_vec();
    bytes.extend_from_slice(claim_id.as_bytes());
    bytes.extend_from_slice(input_binding.as_bytes());
    WorkspaceReviewClaimV1 {
        claim_id,
        envelope_digest: input_binding.into(),
        semantic_decision_digest: Some(digest_bytes(&bytes)),
        legacy_semantic_recovered: false,
        expires_at_ms: None,
    }
}

fn bucket(
    budget: &BusinessBudgetV1,
    input: &PreparedBusinessInputV1,
    actor: &ActorBindings,
) -> Result<String, String> {
    let binding = match budget.scope {
        BusinessBudgetScopeV1::Account => input.facts().provider.account_binding.as_deref(),
        BusinessBudgetScopeV1::User => actor.user.as_deref(),
        BusinessBudgetScopeV1::Workflow => actor.workflow.as_deref(),
    }
    .ok_or_else(|| "native_business_budget_actor_unavailable".to_owned())?;
    if !super::super::super::workspace_review_claim_index::valid_digest(binding) {
        return Err("native_business_budget_actor_unavailable".into());
    }
    // Window/limits/policy generation are deliberately absent: lowering a
    // limit or changing a window must not silently reset previous usage.
    let bytes = canonical_json_bytes(&serde_json::json!({"domain":"guard.business-budget-bucket.v1","id":budget.id,"scope":budget.scope,"binding":binding})).map_err(|_| invalid())?;
    Ok(digest_bytes(&bytes))
}

fn ensure_capacity(
    ledger: &Ledger,
    key: &str,
    budget: &BusinessBudgetV1,
    time: u64,
    volume: &BusinessVolumeV1,
) -> Result<(), String> {
    let mut usage = [
        1,
        volume.recipient_count,
        volume.record_count,
        volume.byte_count,
    ];
    for event in &ledger.events {
        if event.time_ms > time {
            return Err(invalid());
        }
        if time - event.time_ms < budget.window_ms && event.buckets.iter().any(|v| v == key) {
            let addition = [
                1,
                event.volume.recipient_count,
                event.volume.record_count,
                event.volume.byte_count,
            ];
            for (used, added) in usage.iter_mut().zip(addition) {
                *used = used
                    .checked_add(added)
                    .filter(|v| *v <= MAX_BUSINESS_WIRE_COUNT)
                    .ok_or_else(invalid)?;
            }
        }
    }
    let maxima = [
        budget.maximum_actions,
        budget.maximum_recipients,
        budget.maximum_records,
        budget.maximum_bytes,
    ];
    if usage.into_iter().zip(maxima).any(|(used, max)| used > max) {
        return Err("native_business_budget_exceeded".into());
    }
    Ok(())
}

fn path(base: &Path, digest: &str, create: bool) -> Result<(PathBuf, PathBuf), String> {
    if !super::super::super::workspace_review_claim_index::valid_digest(digest) {
        return Err(invalid());
    }
    let root = crate::resident_state::private_root_for_state_base(base)?;
    let directory = base.join(DIRECTORY);
    crate::resident_state::ensure_private_directory_under(&directory, &root, create)?;
    Ok((directory.join(format!("{digest}.json")), root))
}
fn encode(ledger: &Ledger) -> Result<Vec<u8>, String> {
    canonical_json_bytes(&serde_json::to_value(ledger).map_err(|_| invalid())?)
        .map_err(|_| invalid())
}
fn empty_ledger() -> Ledger {
    Ledger {
        schema: "guard.business-budget-ledger.v1".into(),
        version: 1,
        events: Vec::new(),
    }
}
fn load(base: &Path) -> Result<(Ledger, Option<anchor::Anchor>), String> {
    let previous = anchor::load(base)?;
    let Some(saved) = &previous else {
        // Losing the protected anchor cannot bootstrap over existing history.
        if base.join(DIRECTORY).try_exists().map_err(|_| invalid())? {
            return Err("native_business_budget_anchor_missing".into());
        }
        return Ok((empty_ledger(), None));
    };
    if saved.replay_index.claim_count == 0 {
        let ledger = empty_ledger();
        let expected = digest_bytes(&encode(&ledger)?);
        if saved.root != expected || saved.replay_index.root != expected {
            return Err(invalid());
        }
        return Ok((ledger, previous));
    }
    let (file, root) = path(base, &saved.root, false)?;
    let (_, bytes) = super::super::super::policy_store_persistence::read_private_json(
        &file,
        MAX_BYTES,
        "business_budget",
        &root,
    )?
    .ok_or_else(invalid)?;
    if digest_bytes(&bytes) != saved.root {
        return Err(invalid());
    }
    let ledger: Ledger = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if ledger.schema != "guard.business-budget-ledger.v1"
        || ledger.version != 1
        || ledger.events.is_empty()
        || encode(&ledger)? != bytes
    {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    let mut last = 0;
    for event in &ledger.events {
        if replay::find_claim(
            base,
            &saved.replay_index,
            &request_digest(&event.request_id),
        )?
        .as_ref()
            != Some(&budget_claim(&event.request_id, &event.input_binding))
        {
            return Err(invalid());
        }
        if event.time_ms == 0
            || event.time_ms < last
            || event.time_ms > saved.last_time_ms
            || !ids.insert(&event.request_id)
            || !super::super::super::workspace_review_request::valid_request_id(&event.request_id)
            || !super::super::super::workspace_review_claim_index::valid_digest(
                &event.input_binding,
            )
            || event.buckets.is_empty()
            || event.buckets.len() > 256
            || event.buckets.windows(2).any(|v| v[0] >= v[1])
            || event
                .buckets
                .iter()
                .any(|v| !super::super::super::workspace_review_claim_index::valid_digest(v))
            || [
                event.volume.recipient_count,
                event.volume.record_count,
                event.volume.byte_count,
            ]
            .iter()
            .any(|v| *v > MAX_BUSINESS_WIRE_COUNT)
        {
            return Err(invalid());
        }
        last = event.time_ms;
    }
    if last != saved.last_time_ms || saved.replay_index.claim_count < ledger.events.len() as u64 {
        return Err(invalid());
    }
    Ok((ledger, previous))
}

#[cfg(all(test, unix))]
#[path = "workspace_review_business_budget_tests.rs"]
mod tests;

#[cfg(all(test, not(unix)))]
#[test]
fn unsupported_durability_refuses_before_state_access() {
    assert_eq!(
        ensure_durable_platform().unwrap_err(),
        "native_business_budget_durability_unavailable"
    );
}
