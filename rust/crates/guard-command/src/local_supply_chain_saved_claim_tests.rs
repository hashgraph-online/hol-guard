//! What a claimed saved package approval reports back to the caller.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::local_supply_chain::{
    apply_stored_package_policy_override, final_package_protect_authority, ApprovalContextApi,
    PackageEvalApi, PackageIntentParserApi, PackageProtectAuthority, PackageRequestEvaluation,
    PathSupportApi, PolicyDecisionLookup, RuntimeLaunchIdentityApi, SupplyChainStore,
    LOCAL_SUPPLY_CHAIN_HARNESS,
};
use crate::package_execution_context::PackageExecutionContext;
use crate::package_intent_common::{
    build_package_request_artifact, GuardArtifact, PackageIntent, PackageIntentTarget,
};

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
    lookup_error: Option<String>,
    events: RefCell<Vec<(String, Value, String)>>,
    lookup_calls: RefCell<u32>,
    /// When set, lookups after this 1-based call return a store error.
    fail_lookup_after: Option<u32>,
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
        let call = {
            let mut calls = self.lookup_calls.borrow_mut();
            *calls += 1;
            *calls
        };
        if self.fail_lookup_after.is_some_and(|after| call > after) {
            return PolicyDecisionLookup {
                error: Some("native_policy_decision_lookup_query_failed".to_string()),
                ..PolicyDecisionLookup::default()
            };
        }
        if let Some(code) = &self.lookup_error {
            return PolicyDecisionLookup {
                error: Some(code.clone()),
                ..PolicyDecisionLookup::default()
            };
        }
        PolicyDecisionLookup {
            decision: self.decision.clone(),
            ignored_local_integrity: None,
            error: None,
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
    fn add_event(&self, kind: &str, payload: &Value, now: &str) {
        self.events
            .borrow_mut()
            .push((kind.to_string(), payload.clone(), now.to_string()));
    }
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
        Ok(evaluation())
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
        Some(install_intent())
    }
}

impl RuntimeLaunchIdentityApi for Seams {
    fn build_runtime_launch_identity(
        &self,
        _artifact: &GuardArtifact,
        _command: &[String],
    ) -> Value {
        Value::Null
    }
    fn resolved_runtime_launch_argv(&self, command: &[String]) -> Vec<String> {
        command.to_vec()
    }
    fn runtime_launch_identity_is_reusable(&self, _saved: &Value, _current: &Value) -> bool {
        false
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
        lookup_error: None,
        events: RefCell::new(Vec::new()),
        lookup_calls: RefCell::new(0),
        fail_lookup_after: None,
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
    )
    .evaluation;
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
fn a_failed_lookup_keeps_the_review_and_records_its_code() {
    let store = SavedApprovalStore {
        home: PathBuf::from("/tmp/guard-home"),
        decision: Some(json!({
            "decision_id": 7,
            "action": "allow",
            "artifact_hash": ARTIFACT_HASH,
        })),
        claim_succeeds: true,
        claimed: RefCell::new(Vec::new()),
        looked_up: RefCell::new(Vec::new()),
        lookup_error: Some("native_policy_decision_lookup_query_failed".to_string()),
        events: RefCell::new(Vec::new()),
        lookup_calls: RefCell::new(0),
        fail_lookup_after: None,
    };
    let seams = Seams;
    let applied = apply_stored_package_policy_override(
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
    let resolved = &applied.evaluation;
    assert!(store.claimed.borrow().is_empty());
    assert_eq!(resolved.policy_action().as_deref(), Some("review"));
    assert_eq!(resolved.value.get("saved_approval_applied"), None);
    assert_eq!(
        applied.lookup_error.as_deref(),
        Some("native_policy_decision_lookup_query_failed")
    );
    assert_eq!(
        store.events.borrow().as_slice(),
        [(
            "package_policy_lookup_failed".to_string(),
            json!({ "code": "native_policy_decision_lookup_query_failed" }),
            NOW.to_string(),
        )]
    );
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

fn install_intent() -> PackageIntent {
    PackageIntent {
        package_manager: "npm".to_string(),
        intent_kind: "install",
        command_tokens: vec![
            "npm".to_string(),
            "install".to_string(),
            "left-pad".to_string(),
        ],
        redacted_command: "npm install left-pad".to_string(),
        targets: vec![PackageIntentTarget {
            ecosystem: "npm".to_string(),
            package_name: Some("left-pad".to_string()),
            raw_spec: "left-pad".to_string(),
            requested_specifier: None,
            source_url: None,
            source_kind: None,
            source_repository: None,
            source_revision_kind: None,
            source_identity: None,
            source_invalid_reason: None,
            alias: None,
            dependency_group: None,
            extras: Vec::new(),
            editable: false,
        }],
        manifest_paths: Vec::new(),
        lockfile_paths: Vec::new(),
        flags: Vec::new(),
        notes: Vec::new(),
        local_executions: Vec::new(),
        execution_context_hashes: Vec::new(),
        execution_context_cwds: Vec::new(),
        execution_context_reason_codes: Vec::new(),
        routine_local_runner: false,
    }
}

#[test]
fn a_failed_refresh_after_a_consumed_claim_keeps_the_review() {
    let home = std::env::temp_dir().join(format!(
        "hol-guard-refresh-lookup-{}-{}",
        std::process::id(),
        crate::unique_nanos::unique_nanos(),
    ));
    std::fs::create_dir_all(home.join("package-shims").join("bin")).unwrap();
    let workspace = home.join("proj");
    std::fs::create_dir_all(&workspace).unwrap();
    let built = build_package_request_artifact(
        LOCAL_SUPPLY_CHAIN_HARNESS,
        &install_intent(),
        "hol-guard.toml",
        "project",
    );
    let store = SavedApprovalStore {
        home: home.clone(),
        decision: Some(json!({
            "decision_id": 7,
            "action": "allow",
            "artifact_hash": ARTIFACT_HASH,
        })),
        claim_succeeds: true,
        claimed: RefCell::new(Vec::new()),
        looked_up: RefCell::new(Vec::new()),
        lookup_error: None,
        events: RefCell::new(Vec::new()),
        lookup_calls: RefCell::new(0),
        fail_lookup_after: Some(1),
    };
    let initial = PackageProtectAuthority {
        intent: install_intent(),
        artifact: built,
        evaluation: evaluation(),
        current_action: Some(json!("review")),
        execution_context: PackageExecutionContext {
            digest: "d".repeat(64),
            portable: false,
            components: Vec::new(),
            non_portable_reason: None,
        },
        artifact_hash: ARTIFACT_HASH.to_string(),
        launch_identity: Value::Null,
        launch_cwd: workspace.clone(),
        launch_environment: BTreeMap::new(),
        additional_current_action: None,
        additional_policy_context: None,
        observe_mode: false,
        invoking_harness: LOCAL_SUPPLY_CHAIN_HARNESS.to_string(),
    };
    let seams = Seams;
    let bind = |_home: Option<&Path>| {};
    let (_authority, resolved) = final_package_protect_authority(
        initial,
        &evaluation(),
        true,
        &[
            "npm".to_string(),
            "install".to_string(),
            "left-pad".to_string(),
        ],
        &store,
        &workspace,
        NOW,
        None,
        None,
        None,
        &seams,
        &seams,
        &seams,
        &bind,
        &seams,
        &seams,
    )
    .expect("the refresh runs");
    assert_eq!(store.claimed.borrow().len(), 1);
    assert_eq!(*store.lookup_calls.borrow(), 2);
    assert_eq!(resolved.policy_action().as_deref(), Some("review"));
    assert_eq!(resolved.value.get("saved_approval_applied"), None);
    assert_eq!(
        resolved
            .value
            .get("package_policy_lookup_error")
            .and_then(Value::as_str),
        Some("native_policy_decision_lookup_query_failed")
    );
    let _ = std::fs::remove_dir_all(&home);
}
