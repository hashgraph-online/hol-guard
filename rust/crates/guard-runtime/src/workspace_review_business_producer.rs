//! Private verified-input producer for the existing native review authority.
//! No resident RPC, caller facts, credential export or provider dispatch.

use super::*;
use guard_google_identity::directory::PreparedGoogleBusinessRequest;
use serde_json::json;

#[path = "workspace_review_business_journal.rs"]
mod journal;

#[allow(dead_code)] // Reservation/actor integration does not enable a worker route.
#[path = "workspace_review_business_budget.rs"]
mod budget;

#[allow(dead_code)] // No authenticated worker route is published yet.
#[path = "workspace_review_business_dispatch.rs"]
mod dispatch;

// This owned value is never serialized, cloned, or published through an RPC.
// A consumed approval is not dispatch permission until budgets and current
// worker policy have also been enforced by the future registered worker.
#[allow(dead_code)]
pub(crate) struct ClaimedBusinessReview<T> {
    input: T,
    owned: PreparedBusinessInputV1,
    journal: journal::Journal,
    lease: dispatch::Lease,
    verified: super::super::workspace_review_decision::VerifiedWorkspaceReviewDecision,
}
type ClaimedGoogleBusinessRequest = ClaimedBusinessReview<PreparedGoogleBusinessRequest>;

// The managed worker route is deliberately not published as a generic resident
// RPC. These types are kept private until its authenticated route is connected.
#[allow(dead_code)]
pub(crate) struct OwnedGoogleBusinessReview {
    request_id: String,
    input: PreparedGoogleBusinessRequest,
}
#[allow(dead_code)]
impl OwnedGoogleBusinessReview {
    pub(crate) fn request_id(&self) -> &str {
        &self.request_id
    }
    /// Refresh provider evidence before claiming. Changed provider revisions
    /// cannot be silently substituted for the immutable reviewed request.
    /// Expiry after consumption spends the approval without permitting dispatch;
    /// callers must prepare and approve a new request rather than retry it.
    pub(crate) fn claim(
        self,
        store: &super::super::PolicySnapshotStore,
        decision: &[u8],
    ) -> Result<ClaimedGoogleBusinessRequest, String> {
        let binding = self.input.prepared_input().binding().to_owned();
        let refreshed = self
            .input
            .refresh()
            .map_err(|_| "native_business_resolution_unavailable".to_owned())?;
        claim_refreshed_review(
            store,
            &self.request_id,
            decision,
            &binding,
            refreshed,
            PreparedGoogleBusinessRequest::is_current,
            |input| input.prepared_input().binding(),
        )
    }
}

// Shared production boundary after the purpose-bound provider refresh. Tests
// use native frozen inputs here, not exported/fake OAuth credentials. This
// helper never constructs provider evidence or bypasses native signed claims.
fn claim_refreshed_review<T>(
    store: &super::super::PolicySnapshotStore,
    request_id: &str,
    decision: &[u8],
    binding: &str,
    refreshed: T,
    current: impl Fn(&T) -> bool,
    input_binding: impl Fn(&T) -> &str,
) -> Result<ClaimedBusinessReview<T>, String> {
    if !current(&refreshed) || input_binding(&refreshed) != binding {
        return Err("native_business_resolution_changed".into());
    }
    let (verified, owned, (journal, lease)) =
        super::super::workspace_review_decision::claim_owned_business_request_with(
            store,
            request_id,
            decision,
            |owned, observed_at_ms| {
                if owned.binding() != binding {
                    return Err("native_business_claim_input_changed".into());
                }
                let lease = dispatch::Lease::capture(store, decision, observed_at_ms)?;
                let journal =
                    journal::Journal::claimed_unlocked(store, request_id, owned.binding())?;
                Ok((journal, lease))
            },
        )?;
    if owned.binding() != binding {
        return Err("native_business_claim_input_changed".into());
    }
    let lease = lease.seal_clock(verified.observed_at_ms)?;
    if !current(&refreshed) {
        return Err("native_business_claim_expired_after_consume".into());
    }
    Ok(ClaimedBusinessReview {
        input: refreshed,
        owned,
        journal,
        lease,
        verified,
    })
}

#[allow(dead_code)]
pub(crate) fn prepare_google_review(
    store: &super::super::PolicySnapshotStore,
    input: PreparedGoogleBusinessRequest,
) -> Result<OwnedGoogleBusinessReview, String> {
    if !input.is_current() {
        return Err("native_business_resolution_expired".into());
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|_| "native_business_request_id_unavailable".to_owned())?;
    let request_id = format!("business-{}", hex::encode(random));
    persist_prepared_review(store, &request_id, input.prepared_input(), || {
        input.is_current()
    })?;
    Ok(OwnedGoogleBusinessReview { request_id, input })
}

fn persist_prepared_review(
    store: &super::super::PolicySnapshotStore,
    request_id: &str,
    prepared: &PreparedBusinessInputV1,
    current: impl Fn() -> bool,
) -> Result<(), String> {
    if !current() {
        return Err("native_business_resolution_expired".into());
    }
    if !super::super::workspace_review_request::valid_request_id(request_id) {
        return Err(invalid());
    }
    super::super::approval_enrollment::with_transition_lock(store.state_base(), || {
        let snapshot = store.current_snapshot()?;
        crate::policy_enforcement::ensure_business_review_permitted(
            &snapshot,
            prepared.facts(),
            "review",
        )?;
        let private_root = crate::resident_state::private_root_for_state_base(store.state_base())?;
        let directory = store.state_base().join(DIRECTORY);
        let requests = store.state_base().join("workspace-review-requests");
        crate::resident_state::ensure_private_directory_under(&directory, &private_root, true)?;
        crate::resident_state::ensure_private_directory_under(&requests, &private_root, true)?;
        let private_value = json!({"schema":"guard.private-business-input.v1", "version":1,
            "facts":prepared.facts(), "primary_base64":Base64::encode_string(prepared.primary_bytes()),
            "attachments_base64":prepared.attachments().map(Base64::encode_string).collect::<Vec<_>>()});
        let private_bytes = canonical_json_bytes(&private_value).map_err(|_| invalid())?;
        let context = Context {
            schema: "guard.private-business-review.v1".into(),
            version: 1,
            prepared_input_binding: prepared.binding().into(),
            snapshot_digest: digest_bytes(&private_bytes),
        };
        let mut receipt: NativeHookDecisionReceiptV1 = serde_json::from_value(json!({
            "schema":"guard-native-hook-decision-receipt.v1", "version":1, "authority":"rust",
            "decision_id":"", "request_id":request_id, "request_digest":prepared.binding(),
            "execution_intent_digest":prepared.binding(), "harness":"business_worker", "event_name":"BusinessPrepare",
            "payload_kind":"inline", "policy_generation":snapshot.generation,
            "policy_digest":snapshot.policy_digest, "rule_digest":snapshot.rule_digest,
            "runtime_identity":snapshot.runtime_identity, "decision":"review", "model_output_action":"review",
            "policy_action":"review", "observed_policy_action":null, "reason_code":"native_business_review_required",
            "workspace_bound":true, "source_ref_external_allowed":false, "reviewed_output_sha256":null,
            "observe_mode":false, "deadline_budget_ms":null})).map_err(|_| invalid())?;
        receipt.business_review_binding = Some(origin_binding(request_id, &context, &receipt)?);
        let mut identity = serde_json::to_value(&receipt).map_err(|_| invalid())?;
        identity
            .as_object_mut()
            .ok_or_else(invalid)?
            .remove("decision_id");
        receipt.decision_id =
            digest_bytes(&canonical_json_bytes(&identity).map_err(|_| invalid())?);
        super::super::native_review_origin::authenticate(store, &mut receipt)?;
        let state = json!({"schema":"guard-native-workspace-review-request.v1", "version":1,
            "request_id":request_id, "status":"pending", "action":{"action_envelope":{
                "native_origin_receipt":receipt, "business_context":{"schema":context.schema,
                "version":context.version, "prepared_input_binding":context.prepared_input_binding,
                "snapshot_digest":context.snapshot_digest}}},
            "intent":{"service":"google_gmail","operation":"mail_send","account_binding":prepared.facts().provider.account_binding},
            "revision":{"prepared_input_binding":prepared.binding(),"resolution_binding":prepared.facts().target.revision_binding.as_str()},
            "policy":{"generation":snapshot.generation,"digest":snapshot.policy_digest,
                "rule_digest":snapshot.rule_digest,"runtime_identity":snapshot.runtime_identity,
                "scope_digest":snapshot.scope_contract.scope_digest}});
        let state_bytes = canonical_json_bytes(&state).map_err(|_| invalid())?;
        if !current() {
            return Err("native_business_resolution_expired".into());
        }
        let input_path = directory.join(format!("{}.json", context.snapshot_digest));
        let request_path = requests.join(format!("{request_id}.json"));
        let request_limit = 4 * guard_contracts::NATIVE_WORKSPACE_REVIEW_MAX_DECISION_BYTES as u64;
        let read = super::super::policy_store_persistence::read_private_json;
        if read(
            &request_path,
            request_limit,
            "business_request",
            &private_root,
        )?
        .is_some()
        {
            return Err("native_business_request_exists".into());
        }
        let existing = read(
            &input_path,
            MAX_PRIVATE_BYTES,
            "business_input",
            &private_root,
        )?;
        if existing
            .as_ref()
            .is_some_and(|(_, bytes)| bytes != &private_bytes)
        {
            return Err("native_business_snapshot_changed".into());
        }
        let result = (|| {
            if existing.is_none() {
                super::super::policy_store_persistence::persist_private_bytes(
                    &input_path,
                    &private_bytes,
                    MAX_PRIVATE_BYTES,
                    "business_input",
                    &private_root,
                )?;
            }
            super::super::policy_store_persistence::persist_private_bytes(
                &request_path,
                &state_bytes,
                request_limit,
                "business_request",
                &private_root,
            )?;
            if !current() {
                return Err("native_business_resolution_expired".into());
            }
            let loaded = super::super::workspace_review_request::load(store, request_id)?;
            if loaded
                .business_input
                .as_ref()
                .is_none_or(|loaded| loaded.binding() != prepared.binding())
            {
                return Err("native_business_snapshot_changed".into());
            }
            Ok(())
        })();
        if let Err(original) = result {
            let request_cleanup = remove_created_file(
                &request_path,
                &state_bytes,
                request_limit,
                "business_request",
                &private_root,
            );
            let input_cleanup = if existing.is_none() {
                remove_created_file(
                    &input_path,
                    &private_bytes,
                    MAX_PRIVATE_BYTES,
                    "business_input",
                    &private_root,
                )
            } else {
                Ok(())
            };
            request_cleanup.and(input_cleanup)?;
            return Err(original);
        }
        Ok(())
    })
}

// Called under the transition lock, only for paths absent before preparation.
// Validate private-file protections and ownership before removing our bytes.
fn remove_created_file(
    path: &std::path::Path,
    expected: &[u8],
    limit: u64,
    kind: &str,
    root: &std::path::Path,
) -> Result<(), String> {
    let Some((_, bytes)) =
        super::super::policy_store_persistence::read_private_json(path, limit, kind, root)?
    else {
        return Ok(());
    };
    if bytes != expected {
        return Err("native_business_rollback_input_changed".into());
    }
    std::fs::remove_file(path).map_err(|_| "native_business_rollback_failed".into())
}

#[cfg(test)]
#[path = "workspace_review_business_producer_tests.rs"]
mod tests;
