//! Private native origin, exact proof installation and durable consumed evidence.
//! Standalone challenge RPCs never create Cloud-eligible origin records.
use super::{native_cloud_review_consent as consent, PolicySnapshotStore};
use guard_contracts::{
    ApprovalArtifactV4, ApprovalChallengeV4, ApprovalConsumeRequestV4, ApprovalResultV4,
    ApprovalValidateRequestV4, GuardHookEnvelopeV2, WebAuthnAssertionV4,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

const MAX_BYTES: usize = 512 * 1024;
const MAX_RECORDS: usize = 64;
static DELIVERY_LOCK: Mutex<()> = Mutex::new(());
#[path = "native_cloud_review_v4_authority.rs"]
mod authority;
use authority::{bindings, checked_request, current, exact_bindings, nonce_digest, result};
pub(crate) use authority::{block, origin, query, query_renewal, renew, same_business_identity};
#[path = "native_cloud_review_v4_application.rs"]
mod application;
pub(crate) use application::apply_hook;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryRequest {
    pub schema: String,
    pub version: u16,
    pub request_id: String,
    pub decision_receipt_id: Option<String>,
    pub source_claim_hash: Option<String>,
    pub proof: Option<Proof>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RenewalRequest {
    pub schema: String,
    pub version: u16,
    pub request_id: String,
    pub decision_receipt_id: String,
    pub source_claim_hash: String,
    pub original_nonce_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proof {
    pub schema: String,
    pub challenge: ApprovalChallengeV4,
    pub assertion: WebAuthnAssertionV4,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    decision_receipt_id: String,
    source_claim_hash: String,
    artifact: ApprovalArtifactV4,
    validated: ApprovalResultV4,
    authority_fingerprint: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blocked {
    decision_receipt_id: String,
    source_claim_hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Positive {
    consumed_at_ms: u64,
    receipt: ApprovalResultV4,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsumptionStarted {
    nonce_digest: String,
    started_at_ms: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Renewal {
    decision_receipt_id: String,
    source_claim_hash: String,
    original_nonce_digest: String,
    envelope: GuardHookEnvelopeV2,
    challenge: ApprovalChallengeV4,
    consent_revision: u64,
    revocation_epoch: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Origin {
    envelope: GuardHookEnvelopeV2,
    challenge: ApprovalChallengeV4,
    consent_revision: u64,
    revocation_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authority_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_intent_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    renewal: Option<Renewal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumption_started: Option<ConsumptionStarted>,
    installed: Option<Installed>,
    positive: Option<Positive>,
    blocked: Option<Blocked>,
}
impl Origin {
    fn active_challenge(&self) -> &ApprovalChallengeV4 {
        self.renewal
            .as_ref()
            .map_or(&self.challenge, |renewal| &renewal.challenge)
    }
    fn active_envelope(&self) -> &GuardHookEnvelopeV2 {
        self.renewal
            .as_ref()
            .map_or(&self.envelope, |renewal| &renewal.envelope)
    }
}

/// Opaque native-history permission; no resident request can supply this token.
pub(crate) struct DurableInstalledApproval {
    resident_epoch: String,
    nonce: String,
    authority_fingerprint: String,
}
impl DurableInstalledApproval {
    pub(crate) fn resident_epoch(&self) -> &str {
        &self.resident_epoch
    }
    pub(crate) fn authority_fingerprint(&self) -> &str {
        &self.authority_fingerprint
    }
    pub(crate) fn matches(&self, artifact: &ApprovalArtifactV4) -> bool {
        artifact.resident_epoch == self.resident_epoch && artifact.nonce == self.nonce
    }
}
fn durable_token(record: &Origin) -> Result<DurableInstalledApproval, String> {
    let installed = record
        .installed
        .as_ref()
        .ok_or("native_cloud_review_v4_not_installed")?;
    let challenge = record.active_challenge();
    if record.positive.is_some()
        || record.blocked.is_some()
        || record.consumption_started.is_some()
        || installed.validated.authority != "rust"
        || installed.validated.receipt.phase != "validated"
        || installed.validated.receipt.request_id != challenge.request_id
        || installed.validated.receipt.request_digest != challenge.request_digest
        || installed.validated.receipt.action_digest != challenge.action_digest
        || installed.validated.receipt.nonce != challenge.nonce
        || installed.artifact.nonce != challenge.nonce
        || installed.authority_fingerprint.is_empty()
    {
        return Err("native_cloud_review_v4_state_invalid".into());
    }
    Ok(DurableInstalledApproval {
        resident_epoch: installed.artifact.resident_epoch.clone(),
        nonce: installed.artifact.nonce.clone(),
        authority_fingerprint: installed.authority_fingerprint.clone(),
    })
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    records: BTreeMap<String, Origin>,
}

fn load(home: &Path) -> Result<Journal, String> {
    let Some(text) = read_secret(home)? else {
        return Ok(Journal::default());
    };
    let journal: Journal = serde_json::from_str(&text)
        .map_err(|_| "native_cloud_review_v4_state_invalid".to_owned())?;
    if journal.records.len() > MAX_RECORDS {
        return Err("native_cloud_review_v4_state_invalid".into());
    }
    for (request_id, record) in &journal.records {
        if request_id != &record.challenge.request_id {
            return Err("native_cloud_review_v4_state_invalid".into());
        }
        if let Some(renewal) = &record.renewal {
            if !same_business_identity(&record.challenge, &renewal.challenge)
                || record.challenge.nonce == renewal.challenge.nonce
                || nonce_digest(&record.challenge)? != renewal.original_nonce_digest
                || renewal.revocation_epoch != record.revocation_epoch
                || record.authority_fingerprint.is_none()
                || record.execution_intent_digest.is_none()
                || record.blocked.is_some()
                || record.installed.as_ref().is_some_and(|installed| {
                    installed.decision_receipt_id != renewal.decision_receipt_id
                        || installed.source_claim_hash != renewal.source_claim_hash
                })
            {
                return Err("native_cloud_review_v4_state_invalid".into());
            }
        }
        if let Some(started) = &record.consumption_started {
            if record.installed.is_none()
                || record.blocked.is_some()
                || started.started_at_ms == 0
                || started.nonce_digest != nonce_digest(record.active_challenge())?
            {
                return Err("native_cloud_review_v4_state_invalid".into());
            }
        }
    }
    Ok(journal)
}
fn persist(home: &Path, journal: &Journal) -> Result<(), String> {
    let text = serde_json::to_string(journal)
        .map_err(|_| "native_cloud_review_v4_state_invalid".to_owned())?;
    if text.len() > MAX_BYTES {
        return Err("native_cloud_review_v4_state_full".into());
    }
    write_secret(home, &text)
}
pub(crate) fn install(
    mut request: DeliveryRequest,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    checked_request(&request, "guard-native-cloud-review-install-request.v4")?;
    let proof = request.proof.take();
    let (decision, source) = exact_bindings(&request)?;
    let proof = proof.ok_or("native_cloud_review_v4_proof_missing")?;
    let _consent = consent::CONSENT_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_consent_unavailable".to_owned())?;
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let mut journal = load(store.state_base())?;
    let record = journal
        .records
        .get_mut(&request.request_id)
        .ok_or("native_cloud_review_v4_origin_missing")?;
    if record.installed.is_some() || record.renewal.is_some() || record.blocked.is_some() {
        let (bound_decision, bound_source) = bindings(record)?;
        if bound_decision != decision || bound_source != source {
            return Err("native_cloud_review_v4_immutable_binding_conflict".into());
        }
    }
    if record.positive.is_some() {
        return result(&request.request_id, record);
    }
    current(record, store)?;
    if record.blocked.is_some() {
        return Err("native_cloud_review_v4_immutable_binding_conflict".into());
    }
    if record.renewal.is_some() {
        let original_authority = record
            .authority_fingerprint
            .as_deref()
            .ok_or("native_cloud_review_v4_original_authority_unavailable")?;
        super::approval_v4_authority::verify_renewal_authority(
            store.approval_v4_authority()?,
            &record.challenge,
            original_authority,
        )?;
    }
    if proof.schema != "guard-native-approval-proof.v4"
        || &proof.challenge != record.active_challenge()
        || proof.assertion.assertion_type != "public-key"
    {
        return Err("native_cloud_review_v4_original_challenge_mismatch".into());
    }
    let artifact = ApprovalArtifactV4::from_challenge(proof.challenge, proof.assertion);
    let already_installed = record
        .installed
        .as_ref()
        .is_some_and(|installed| installed.artifact == artifact);
    if already_installed {
        let installed = record
            .installed
            .as_ref()
            .ok_or("native_cloud_review_v4_not_installed")?;
        let durable = durable_token(record)?;
        crate::approval::approval_v4::verify_installed_approval(
            record.active_envelope(),
            &installed.artifact,
            store,
            &durable,
        )?;
    } else {
        if record
            .installed
            .as_ref()
            .is_some_and(|installed| installed.artifact.nonce == artifact.nonce)
        {
            return Err("native_cloud_review_v4_immutable_binding_conflict".into());
        }
        let envelope = record.active_envelope().clone();
        crate::approval::approval_v4::validate_approval_with_emit(
            ApprovalValidateRequestV4 {
                schema: "guard-native-approval-validate-request.v4".into(),
                version: 4,
                envelope,
                artifact: artifact.clone(),
            },
            store,
            |validated, authority_fingerprint| {
                journal
                    .records
                    .get_mut(&request.request_id)
                    .ok_or("native_cloud_review_v4_origin_missing")?
                    .installed = Some(Installed {
                    decision_receipt_id: decision.into(),
                    source_claim_hash: source.into(),
                    artifact: artifact.clone(),
                    validated: validated.clone(),
                    authority_fingerprint: authority_fingerprint.into(),
                });
                persist(store.state_base(), &journal)
            },
        )?;
    }
    result(
        &request.request_id,
        journal
            .records
            .get(&request.request_id)
            .ok_or("native_cloud_review_v4_origin_missing")?,
    )
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiscoveryRequest {
    schema: String,
    version: u32,
    limit: usize,
    after_request_id: Option<String>,
}

/// Historical evidence discovery only; never installs, restores or consumes.
pub(crate) fn discover(
    request: DiscoveryRequest,
    store: &PolicySnapshotStore,
) -> Result<Vec<u8>, String> {
    if request.schema != "guard-native-cloud-review-discovery-request.v4"
        || request.version != 4
        || request.limit == 0
        || request.limit > 8
        || request
            .after_request_id
            .as_ref()
            .is_some_and(|id| id.is_empty() || id.len() > 256)
    {
        return Err("native_cloud_review_v4_discovery_request_invalid".into());
    }
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let journal = load(store.state_base())?;
    let mut records: Vec<_> = journal
        .records
        .iter()
        .filter(|(id, record)| {
            record.positive.is_some()
                && request
                    .after_request_id
                    .as_ref()
                    .is_none_or(|after| id.as_str() > after.as_str())
        })
        .collect();
    records.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    let has_more = records.len() > request.limit;
    let mut observations = Vec::with_capacity(request.limit.min(records.len()));
    for (id, record) in records.iter().take(request.limit) {
        observations.push(
            serde_json::from_slice::<serde_json::Value>(&result(id, record)?)
                .map_err(|_| "native_cloud_review_v4_positive_invalid".to_owned())?,
        );
    }
    let next = if has_more {
        records.get(request.limit - 1).map(|(id, _)| id.as_str())
    } else {
        None
    };
    crate::encode_response(&json!({
        "schema": "guard-native-cloud-review-discovery-result.v4", "version": 4,
        "observations": observations, "next_after_request_id": next
    }))
}

pub(crate) fn reject_standalone_cloud_consumption(
    artifact: &ApprovalArtifactV4,
    store: &PolicySnapshotStore,
) -> Result<(), String> {
    let _transaction = consent::transaction(store.state_base())?;
    let _lock = DELIVERY_LOCK
        .lock()
        .map_err(|_| "native_cloud_review_v4_state_unavailable".to_owned())?;
    let journal = load(store.state_base())?;
    if journal.records.values().any(|origin| {
        let original = origin.challenge.nonce == artifact.nonce
            && origin.challenge.resident_epoch == artifact.resident_epoch;
        let renewed = origin.renewal.as_ref().is_some_and(|renewal| {
            renewal.challenge.nonce == artifact.nonce
                && renewal.challenge.resident_epoch == artifact.resident_epoch
        });
        original || renewed
    }) {
        return Err("native_cloud_review_v4_requires_actual_hook".into());
    }
    Ok(())
}

#[cfg(not(test))]
fn account(home: &Path) -> Result<String, String> {
    Ok(format!(
        "{}:cloud-review-v4-journal",
        super::approval_enrollment::account_for_state_base(home)?
    ))
}
#[cfg(not(test))]
fn read_secret(home: &Path) -> Result<Option<String>, String> {
    super::approval_enrollment::read_platform_secret_for_v4_state(home, &account(home)?, MAX_BYTES)
}
#[cfg(not(test))]
fn write_secret(home: &Path, text: &str) -> Result<(), String> {
    super::approval_enrollment::write_platform_secret_for_v4_state(
        home,
        &account(home)?,
        text,
        MAX_BYTES,
    )
}
#[cfg(test)]
fn read_secret(home: &Path) -> Result<Option<String>, String> {
    Ok(super::policy_store_persistence::read_private_json(
        &home.join("cloud-review-v4-journal.test.json"),
        MAX_BYTES as u64,
        "cloud_review_v4",
        home,
    )?
    .map(|(_, bytes)| String::from_utf8_lossy(&bytes).into_owned()))
}
#[cfg(test)]
fn write_secret(home: &Path, text: &str) -> Result<(), String> {
    super::policy_store_persistence::persist_private_bytes(
        &home.join("cloud-review-v4-journal.test.json"),
        text.as_bytes(),
        MAX_BYTES as u64,
        "cloud_review_v4",
        home,
    )
}
