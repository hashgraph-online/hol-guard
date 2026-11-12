//! Optional explicit-executor preparation, outside the actual launch fence.
//! These native-captured facts have no wire deserialization or approval power.
use crate::policy_enforcement::AdmittedPolicySnapshot;
use guard_contracts::{GuardHookEnvelopeV2, NativeBashCaptureV1, NativeBashSubjectV1};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct Facts {
    pub(crate) home: PathBuf,
    pub(crate) workspace: PathBuf,
    pub(crate) harness: String,
    pub(crate) artifact_hash: String,
    pub(crate) policy_generation: u64,
    pub(crate) policy_digest: String,
    pub(crate) sdk_intent: String,
    pub(crate) effect_id: String,
    pub(crate) text: String,
    pub(crate) expires: Instant,
}

pub(super) fn facts(
    request: &NativeBashCaptureV1,
    envelope: &GuardHookEnvelopeV2,
    subject: &NativeBashSubjectV1,
    snapshot: &AdmittedPolicySnapshot,
    artifact_hash: &str,
) -> Result<Facts, String> {
    if !matches!(request.harness.as_str(), "pi" | "omp") {
        return Err("native_context_execution_harness_unqualified".into());
    }
    if !super::bash_grant::context_matches(request, envelope) {
        return Err("native_context_execution_context_mismatch".into());
    }
    let workspace = std::fs::canonicalize(&request.workspace)
        .map_err(|_| "native_context_execution_workspace_unavailable")?;
    let home = std::fs::canonicalize(&request.guard_home)
        .map_err(|_| "native_context_execution_home_unavailable")?;
    let native_intent = crate::edge::execution_intent_digest(envelope)?;
    let subject = subject.identity_sha256().map_err(str::to_owned)?;
    let policy_generation = snapshot.generation;
    let policy_digest = snapshot.policy_digest.clone();
    let sdk_intent =
        format!("1220{:x}", Sha256::digest(serde_json::to_vec(&json!({
        "schema":"guard-cigar-native-execution-intent.v1", "native_intent":native_intent,
        "captured_subject":subject, "artifact_hash":artifact_hash,
        "policy_generation":policy_generation, "policy_digest":policy_digest,
    })).map_err(|_| "native_context_execution_intent_invalid")?));
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| "native_context_execution_nonce_unavailable")?;
    let effect_id = format!("execution:{:x}", Sha256::digest(nonce));
    let text = format!("Native captured Bash observation for {effect_id}, policy generation {policy_generation}. The captured subject and semantic tool intent are bound by native commitment. Guard still requires its own authorization. This data confirms no dispatch or completion.");
    Ok(Facts {
        home,
        workspace,
        harness: request.harness.clone(),
        artifact_hash: artifact_hash.into(),
        policy_generation,
        policy_digest,
        sdk_intent,
        effect_id,
        text,
        expires: Instant::now() + Duration::from_secs(30),
    })
}
