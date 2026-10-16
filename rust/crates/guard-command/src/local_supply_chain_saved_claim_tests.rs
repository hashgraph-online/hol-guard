//! What a claimed saved package approval reports back to the caller.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::local_supply_chain::{
    apply_stored_package_policy_override, ApprovalContextApi, PackageEvalApi,
    PackageIntentParserApi, PackageRequestEvaluation, PathSupportApi, PolicyDecisionLookup,
    SupplyChainStore,
};
use crate::package_intent_common::{GuardArtifact, PackageIntent};

const ARTIFACT_HASH: &str = "guard-approval-context:v1:abc";

/// One lookup the store answered: harness, artifact id, artifact hash and the
/// workspace identity it was probed with.
type LookedUpCall = (String, String, Option<String>, String);

/// A store whose lookup returns the one saved row the claim reads, and whose
/// claim answers as the caller asked, recording what it was claimed with.
struct SavedApprovalStore {
    home: PathBuf,
    decision: Option<Value>,
    claim_succeeds: bool,
    claimed: RefCell<Vec<(Value, String)>>,
    looked_up: RefCell<Vec<LookedUpCall>>,
}

impl SupplyChainStore for SavedApprovalStore {
    fn guard_home(&self) -> &Path {
        &self.home
    }
    fn get_cloud_sync_profile(&self) -> Option<Value> {
        None
    }
    fn get_cloud_workspace_id(&self) -> Option<String> {
        None
    }
    fn get_cached_supply_chain_bundle(&self, _workspace_id: &str) -> Option<Value> {
        None
    }
    fn get_sync_payload(&self, _key: &str) -> Option<Value> {
        None
    }
    fn set_sync_payload(&self, _key: &str, _payload: &Value) {}
    fn list_cached_advisories(&self) -> Vec<Value> {
        Vec::new()
    }
    fn list_managed_installs(&self) -> Vec<Value> {
        Vec::new()
    }
    fn record_latest_guard_connect_sync_result(
        &self,
        _status: &str,
        _milestone: &str,
        _now: &str,
        _reason: Option<&str>,
    ) {
    }
    fn get_approval_request(&self, _request_id: &str) -> Option<Value> {
        None
    }
    fn resolve_policy_decision_lookup(
        &self,
        harness: &str,
        artifact_id: &str,
        artifact_hash: Option<&str>,
        workspace: &str,
        _publisher: Option<&str>,
        _now: &str,
        _consume_one_shot: bool,
    ) -> PolicyDecisionLookup {
        self.looked_up.borrow_mut().push((
            harness.to_string(),
            artifact_id.to_string(),
            artifact_hash.map(str::to_string),
            workspace.to_string(),
        ));
        PolicyDecisionLookup {
            decision: self.decision.clone(),
            ignored_local_integrity: None,
        }
    }
    fn approval_reuse_diagnostic(
        &self,
        _harness: &str,
        _artifact_id: &str,
        _artifact_hash: &str,
        _workspace: &str,
        _publisher: Option<&str>,
        _now: &str,
    ) -> (Option<String>, Option<String>) {
        (None, None)
    }
    fn approval_reuse_claim_disposition(&self, _decision: &Value) -> Option<String> {
        Some("retained".to_string())
    }
    fn claim_approval_reuse_decision(&self, decision: &Value, now: &str) -> bool {
        self.claimed
            .borrow_mut()
            .push((decision.clone(), now.to_string()));
        self.claim_succeeds
    }
    fn claim_local_once_approval(
        &self,
        _approval_id: &str,
        _claimed_at: &str,
        _expected_decision: &Value,
    ) -> bool {
        false
    }
    fn add_receipt(&self, _receipt: &Value) {}
    fn set_receipt_action_envelope(&self, _receipt_id: &str, _metadata: &Value) {}
    fn add_event(&self, _kind: &str, _payload: &Value, _now: &str) {}
}

/// The seams the claim path never reaches for a saved row it can read.
struct Seams;

impl PackageEvalApi for Seams {
    fn evaluate_package_request_artifact(
        &self,
        _artifact: &GuardArtifact,
        _store: &dyn SupplyChainStore,
        _workspace_dir: &Path,
        _now: &str,
        _external_archive_network_authorized: bool,
        _retain_external_archive_blob: bool,
    ) -> Result<PackageRequestEvaluation, String> {
        Err("not evaluated".to_string())
    }
    fn supply_chain_user_copy(
        &self,
        _title: &str,
        _summary: &str,
        _next_step: Option<&str>,
        _dashboard_url: Option<&str>,
        _harness_message: Option<&str>,
    ) -> Map<String, Value> {
        Map::new()
    }
}

impl PackageIntentParserApi for Seams {
    fn parse_package_intent(
        &self,
        _command: &str,
        _workspace: &Path,
        _environment: &BTreeMap<String, String>,
    ) -> Option<PackageIntent> {
        None
    }
}

impl PathSupportApi for Seams {
    fn resolve_path_within_allowed_roots(
        &self,
        _candidate: &Path,
        _allowed_roots: &[PathBuf],
        _require_exists: bool,
    ) -> Option<PathBuf> {
        None
    }
    fn resolves_within_root(&self, _root: &Path, _candidate: &Path, _require_exists: bool) -> bool {
        false
    }
    fn read_text_within_workspace(
        &self,
        _workspace_dir: &Path,
        _relative_path: &str,
    ) -> Option<String> {
        None
    }
    fn read_bytes_within_workspace(
        &self,
        _workspace_dir: &Path,
        _relative_path: &str,
    ) -> Option<Vec<u8>> {
        None
    }
}

impl ApprovalContextApi for Seams {
    fn parse_approval_context_token(&self, _token: &Value) -> Option<Value> {
        None
    }
    fn approval_context_tokens_validation_reason(
        &self,
        _saved_token: &Value,
        _current_token: &Value,
    ) -> Option<String> {
        None
    }
    fn build_approval_context_token(
        &self,
        _identity: &Value,
        _content: &Value,
        _capabilities: &Value,
        _policy: &Value,
        _sandbox: &Value,
    ) -> String {
        String::new()
    }
    fn saved_allow_context_validation_reason(
        &self,
        _decision: &Value,
        _artifact_hash: &str,
    ) -> Option<String> {
        None
    }
}

fn artifact() -> GuardArtifact {
    GuardArtifact {
        artifact_id: "codex:package-request:npm:left-pad".to_string(),
        name: "package-request".to_string(),
        harness: "codex".to_string(),
        artifact_type: "package-request".to_string(),
        source_scope: "workspace".to_string(),
        config_path: "/tmp/proj/.mcp.json".to_string(),
        command: None,
        args: Vec::new(),
        url: None,
        transport: None,
        publisher: None,
        metadata: json!({}),
        runtime_private_metadata: json!({}),
    }
}

fn evaluation() -> PackageRequestEvaluation {
    PackageRequestEvaluation::new(json!({
        "decision": "review",
        "policy_action": "review",
        "packages": [{"name": "left-pad", "ecosystem": "npm"}],
        "reasons": ["package request"],
    }))
}

const NOW: &str = "2026-01-01T00:00:00+00:00";

/// One lookup the store was asked for: harness, artifact id, artifact hash and
/// workspace identity.
type RecordedLookup = (String, String, Option<String>, String);

/// The evaluation the override resolves, the rows the store was asked to claim
/// while resolving it, and the lookups it was asked for.
fn resolve_recording(
    decision: Option<Value>,
    claim_succeeds: bool,
) -> (
    PackageRequestEvaluation,
    Vec<(Value, String)>,
    Vec<RecordedLookup>,
) {
    let store = SavedApprovalStore {
        home: PathBuf::from("/tmp/guard-home"),
        decision,
        claim_succeeds,
        claimed: RefCell::new(Vec::new()),
        looked_up: RefCell::new(Vec::new()),
    };
    let seams = Seams;
    let resolved = apply_stored_package_policy_override(
        &evaluation(),
        &store,
        &artifact(),
        ARTIFACT_HASH,
        Path::new("/tmp/proj"),
        NOW,
        None,
        None,
        true,
        &seams,
        &seams,
        &seams,
        &seams,
    );
    let claimed = store.claimed.borrow().clone();
    let looked_up = store.looked_up.borrow().clone();
    (resolved, claimed, looked_up)
}

fn resolve_with_claim(
    decision: Option<Value>,
    claim_succeeds: bool,
) -> (PackageRequestEvaluation, Vec<(Value, String)>) {
    let (resolved, claimed, _) = resolve_recording(decision, claim_succeeds);
    (resolved, claimed)
}

fn resolve(decision: Option<Value>) -> PackageRequestEvaluation {
    resolve_with_claim(decision, true).0
}

#[test]
fn a_claimed_saved_approval_rewrites_the_evaluation() {
    let row = json!({
        "decision_id": 7,
        "action": "allow",
        "artifact_hash": ARTIFACT_HASH,
    });
    let (claimed, claims) = resolve_with_claim(Some(row.clone()), true);
    // The row the evaluation reports as approved is the row the store was
    // asked to claim, at the resolution's own timestamp.
    assert_eq!(claims, vec![(row, NOW.to_string())]);
    assert_eq!(claimed.policy_action().as_deref(), Some("allow"));
    assert_eq!(claimed.decision_value(), "allow");
    assert_eq!(claimed.value["saved_approval_applied"], json!(true));
    assert_eq!(claimed.value["saved_approval_decision_id"], json!(7));
    // The rest of the evaluation is carried through untouched.
    assert_eq!(claimed.value["packages"][0]["name"], "left-pad");
}

#[test]
fn a_refused_claim_leaves_the_review_verdict_standing() {
    let row = json!({
        "decision_id": 7,
        "action": "allow",
        "artifact_hash": ARTIFACT_HASH,
    });
    let (unchanged, claims) = resolve_with_claim(Some(row.clone()), false);
    assert_eq!(claims, vec![(row, NOW.to_string())]);
    // Another caller took the single-use row, so it is not reported as an
    // approval the way a claimed row is.
    assert_eq!(unchanged.policy_action().as_deref(), Some("review"));
    assert_eq!(unchanged.decision_value(), "review");
    assert_eq!(unchanged.value.get("saved_approval_applied"), None);
    assert_eq!(unchanged.value.get("saved_approval_decision_id"), None);
}

#[test]
fn a_saved_row_for_another_content_hash_leaves_the_evaluation_alone() {
    let (unchanged, claims) = resolve_with_claim(
        Some(json!({
            "decision_id": 7,
            "action": "allow",
            "artifact_hash": "guard-approval-context:v1:other",
        })),
        true,
    );
    // A row for other content is never claimed at all.
    assert!(claims.is_empty());
    assert_eq!(unchanged.policy_action().as_deref(), Some("review"));
    assert_eq!(unchanged.value.get("saved_approval_applied"), None);
}

#[test]
fn no_saved_row_leaves_the_evaluation_alone() {
    let unchanged = resolve(None);
    assert_eq!(unchanged.policy_action().as_deref(), Some("review"));
    assert_eq!(unchanged.value.get("saved_approval_applied"), None);
}

#[test]
fn a_saved_row_recording_another_action_is_not_claimed_as_an_approval() {
    for action in ["block", "review", "require-reapproval"] {
        let (unchanged, claims) = resolve_with_claim(
            Some(json!({
                "decision_id": 7,
                "action": action,
                "artifact_hash": ARTIFACT_HASH,
            })),
            true,
        );
        // The lanes that own a block or a review row read it themselves; the
        // claim is never spent on one.
        assert!(claims.is_empty(), "{action}");
        assert_eq!(
            unchanged.policy_action().as_deref(),
            Some("review"),
            "{action}"
        );
        assert_eq!(
            unchanged.value.get("saved_approval_applied"),
            None,
            "{action}"
        );
    }
    // A row with no action at all is read the same way.
    let unchanged = resolve(Some(json!({
        "decision_id": 7,
        "artifact_hash": ARTIFACT_HASH,
    })));
    assert_eq!(unchanged.value.get("saved_approval_applied"), None);
}

#[test]
fn the_saved_row_is_looked_up_under_the_artifacts_harness_and_workspace_identity() {
    let row = json!({
        "decision_id": 7,
        "action": "allow",
        "artifact_hash": ARTIFACT_HASH,
    });
    let (_, _, lookups) = resolve_recording(Some(row), true);
    let (harness, artifact_id, artifact_hash, workspace) =
        lookups.first().expect("the store was asked for a lookup");
    assert_eq!(harness, "codex");
    assert_eq!(artifact_id, "codex:package-request:npm:left-pad");
    assert_eq!(artifact_hash.as_deref(), Some(ARTIFACT_HASH));
    // The lookup is scoped by the runtime workspace identity a package
    // approval is saved under, never by the workspace path.
    assert_ne!(workspace, "/tmp/proj");
    assert!(
        workspace.starts_with("package-request-workspace"),
        "{workspace}"
    );
}
