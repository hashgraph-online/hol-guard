use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::local_supply_chain::{
    stored_package_policy_is_stale_policy_bundle_family, PolicyDecisionLookup, SupplyChainStore,
};
use crate::package_intent_common::GuardArtifact;

struct PolicyBundleStore {
    home: PathBuf,
    bundle: Option<Value>,
}

impl SupplyChainStore for PolicyBundleStore {
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
    fn get_sync_payload(&self, key: &str) -> Option<Value> {
        (key == "policy_bundle")
            .then(|| self.bundle.clone())
            .flatten()
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
        _harness: &str,
        _artifact_id: &str,
        _artifact_hash: Option<&str>,
        _workspace: &str,
        _publisher: Option<&str>,
        _now: &str,
        _consume_one_shot: bool,
    ) -> PolicyDecisionLookup {
        PolicyDecisionLookup::default()
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
        None
    }
    fn claim_approval_reuse_decision(&self, _decision: &Value, _now: &str) -> bool {
        false
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

fn artifact() -> GuardArtifact {
    GuardArtifact {
        artifact_id: "family:package-request".to_string(),
        name: "package-request".to_string(),
        harness: "codex".to_string(),
        artifact_type: "package-request".to_string(),
        source_scope: "workspace".to_string(),
        config_path: "/tmp/proj".to_string(),
        command: None,
        args: Vec::new(),
        url: None,
        transport: None,
        publisher: None,
        metadata: json!({}),
        runtime_private_metadata: json!({}),
    }
}

fn store_with_unrelated_rule() -> PolicyBundleStore {
    PolicyBundleStore {
        home: PathBuf::from("/tmp/guard-home"),
        bundle: Some(json!({
            "policyVersion": "1",
            "rules": [{"ruleId": "some-other-rule"}],
        })),
    }
}

fn stored_row(artifact_hash: Option<Value>) -> Value {
    let mut row = json!({
        "source": "policy-bundle",
        "artifact_id": "family:package-request",
        "scope": "global",
        "owner": "rule-removed-from-bundle",
    });
    if let Some(hash) = artifact_hash {
        row["artifact_hash"] = hash;
    }
    row
}

#[test]
fn null_artifact_hash_is_treated_as_absent() {
    let store = store_with_unrelated_rule();
    for row in [stored_row(None), stored_row(Some(Value::Null))] {
        assert!(stored_package_policy_is_stale_policy_bundle_family(
            &store,
            &row,
            &artifact()
        ));
    }
}

#[test]
fn concrete_artifact_hash_is_not_a_family_override() {
    let store = store_with_unrelated_rule();
    let row = stored_row(Some(json!("sha256:abc")));
    assert!(!stored_package_policy_is_stale_policy_bundle_family(
        &store,
        &row,
        &artifact()
    ));
}
