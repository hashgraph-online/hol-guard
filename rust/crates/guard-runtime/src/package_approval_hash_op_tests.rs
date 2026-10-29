//! Parity vectors recorded from the legacy Python `local_supply_chain`
//! approval-hash path before it was deleted. Their policy digests were later
//! recomputed when bundle and feed revisions left the policy context,
//! reasons were reduced to their codes, and the matched rule and advisories
//! left it.

use super::*;
use guard_contracts::PackageApprovalHashRequestV1;
use serde_json::{json, Value};
use std::path::PathBuf;

const VECTORS: &str = include_str!("../testdata/package_approval_hash_vectors.json");

struct Workspace(PathBuf);

impl Workspace {
    fn new(name: &str) -> Self {
        let nonce = crate::unique_nanos::unique_nanos();
        let root = std::env::temp_dir().join(format!(
            "hol-guard-approval-hash-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn request(vector: &Value, workspace: &Workspace, kind: &str) -> PackageApprovalHashRequestV1 {
    let root = &workspace.0;
    for (relative, text) in vector["workspace_files"].as_object().unwrap() {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text.as_str().unwrap()).unwrap();
    }
    let db = root.join("guard.db");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE publisher_cache (publisher_key TEXT PRIMARY KEY, payload_json TEXT NOT NULL, updated_at TEXT NOT NULL)",
        )
        .unwrap();
    for (index, row) in vector["advisory_rows"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        connection
            .execute(
                "INSERT INTO publisher_cache VALUES (?1, ?2, ?3)",
                rusqlite::params![index.to_string(), row.to_string(), format!("{index:03}")],
            )
            .unwrap();
    }
    drop(connection);
    let mut value = vector["request"].clone();
    let map = value.as_object_mut().unwrap();
    map.insert("schema".into(), json!(PACKAGE_AUTHORITY_REQUEST_SCHEMA));
    map.insert("request_id".into(), json!("vector"));
    map.insert("guard_home".into(), json!(root.to_string_lossy()));
    map.insert("kind".into(), json!(kind));
    if kind == "artifact_hash" {
        map.insert("store_path".into(), json!(db.to_string_lossy()));
        map.insert("workspace_dir".into(), json!(root.to_string_lossy()));
    } else {
        for key in [
            "execution_context",
            "extension_control_digest",
            "feed_snapshot_hash",
            "launch_identity",
            "additional_policy_context",
            "sandbox_analysis",
        ] {
            map.remove(key);
        }
    }
    serde_json::from_value(value).unwrap()
}

fn run(request: &PackageApprovalHashRequestV1) -> Result<Value, String> {
    evaluate_package_approval_hash(request)
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone())
}

#[test]
fn recorded_python_vectors_match() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 10);
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        // A recorded view is replayed through the fields it hydrates from:
        // the wire path no longer takes a resolved view. The in-process form
        // is covered by `the_relay_may_send_a_view_the_wire_may_not`.
        let replayed = match vector["config_facts"].is_null() {
            true => (*vector).clone(),
            false => with_config_facts(vector),
        };
        let vector = &replayed;
        let workspace = Workspace::new(name);
        let hashed = run(&request(vector, &workspace, "artifact_hash")).unwrap();
        assert_eq!(
            hashed["artifact_hash"], vector["expected"]["artifact_hash"],
            "{name}"
        );
        assert_eq!(
            hashed["current_action"], vector["expected"]["current_action"],
            "{name}"
        );
        let workspace = Workspace::new(name);
        let action = run(&request(vector, &workspace, "current_action")).unwrap();
        assert_eq!(
            action,
            json!({"current_action": vector["expected"]["current_action"]}),
            "{name}"
        );
    }
}

#[test]
fn rejects_malformed_requests() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let workspace = Workspace::new("reject");
    let good = request(&vectors[0], &workspace, "artifact_hash");

    let mut unknown_kind = good.clone();
    unknown_kind.kind = "other".into();
    assert_eq!(
        run(&unknown_kind).unwrap_err(),
        "native_package_approval_hash_invalid"
    );

    let mut schema = good.clone();
    schema.schema = "wrong".into();
    assert_eq!(
        run(&schema).unwrap_err(),
        "native_package_approval_hash_schema_mismatch"
    );

    let mut context = good.clone();
    context.execution_context = Some(json!({"digest": "d", "version": 1, "components": []}));
    assert_eq!(
        run(&context).unwrap_err(),
        "native_package_approval_hash_invalid"
    );

    let mut missing_digest = good;
    missing_digest.extension_control_digest = None;
    assert_eq!(
        run(&missing_digest).unwrap_err(),
        "native_package_approval_hash_invalid"
    );
}

/// The same vector with the configuration fields in place of the view they
/// hydrate, as the caller holding a loaded `GuardConfig` sends it.
fn with_config_facts(vector: &Value) -> Value {
    let mut vector = vector.clone();
    let facts = vector["config_facts"].clone();
    let request = vector["request"].as_object_mut().unwrap();
    request.remove("config_policy");
    request.insert("config_facts".to_owned(), facts);
    vector
}

/// The resident hydrates the bound policy view from the sent fields, so an
/// approval saved against the view Python used to send stays valid: the hash
/// binds the same bytes and the composed action is the same.
#[test]
fn hydrated_config_facts_reproduce_the_sent_view() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let mut covered = 0;
    for vector in &vectors {
        if vector["config_facts"].is_null() {
            continue;
        }
        covered += 1;
        let name = vector["name"].as_str().unwrap();
        let workspace = Workspace::new(name);
        let hydrated = run(&request(
            &with_config_facts(vector),
            &workspace,
            "artifact_hash",
        ))
        .unwrap();
        assert_eq!(
            hydrated["artifact_hash"], vector["expected"]["artifact_hash"],
            "{name}"
        );
        assert_eq!(
            hydrated["current_action"], vector["expected"]["current_action"],
            "{name}"
        );
    }
    assert!(covered >= 3, "no configured vector exercised the fields");
}

/// Exactly one source per request: a request carrying both, and one carrying a
/// field the mirror cannot read, defer rather than deciding under a guess.
#[test]
fn an_unreadable_or_doubled_configuration_defers() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let vector = vectors
        .iter()
        .find(|vector| vector["name"] == "config_harness_block_managed")
        .unwrap();

    let mut both = with_config_facts(vector);
    both["request"]["config_policy"] = vector["request"]["config_policy"].clone();
    let workspace = Workspace::new("both");
    assert_eq!(
        run(&request(&both, &workspace, "artifact_hash")).unwrap_err(),
        "native_package_approval_hash_invalid"
    );

    for key in ["harness_actions", "risk_actions", "security_level", "mode"] {
        let mut broken = with_config_facts(vector);
        broken["request"]["config_facts"]
            .as_object_mut()
            .unwrap()
            .remove(key);
        let workspace = Workspace::new("broken");
        assert_eq!(
            run(&request(&broken, &workspace, "artifact_hash")).unwrap_err(),
            "native_package_approval_hash_invalid",
            "a missing {key} should defer"
        );
    }
}

/// `evaluate_package_approval_hash` is the resident's wire entry point, so a
/// request that carried a resolved view would let whoever sent those bytes
/// pick the `package_script` action and the override folded into the composed
/// action. Only the "no configuration bound" marker is accepted there. The
/// relay reaches the same resolution in process and still sends its view.
#[test]
fn the_relay_may_send_a_view_the_wire_may_not() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let vector = vectors
        .iter()
        .find(|vector| vector["name"] == "config_harness_block_managed")
        .unwrap();

    let workspace = Workspace::new("wire-view");
    let wire = request(vector, &workspace, "artifact_hash");
    assert_eq!(
        run(&wire).unwrap_err(),
        "native_package_approval_hash_invalid"
    );
    let (action, hash) = package_current_action_and_hash(&wire).unwrap();
    assert_eq!(json!(action.as_str()), vector["expected"]["current_action"]);
    assert_eq!(json!(hash), vector["expected"]["artifact_hash"]);

    let workspace = Workspace::new("wire-marker");
    let mut marker = request(vector, &workspace, "current_action");
    marker.config_policy = json!({"available": false});
    assert!(run(&marker).is_ok());

    // The marker with a resolved action smuggled beside it is still a view.
    let workspace = Workspace::new("wire-marker-plus");
    let mut smuggled = request(vector, &workspace, "current_action");
    smuggled.config_policy = json!({
        "available": false,
        "effective_package_script_action": "allow",
    });
    assert_eq!(
        run(&smuggled).unwrap_err(),
        "native_package_approval_hash_invalid"
    );
}

fn advisory_vector() -> Value {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    vectors
        .into_iter()
        .find(|vector| vector["name"] == "advisory_feed_launch_additional")
        .unwrap()
}

fn context_token(vector: &Value, name: &str) -> Value {
    let workspace = Workspace::new(name);
    run(&request(vector, &workspace, "artifact_hash")).unwrap()["artifact_hash"].clone()
}

fn scored_vector() -> Value {
    let mut vector = advisory_vector();
    let package = &mut vector["request"]["evaluation"]["packages"][0];
    package["decision"] = json!("warn");
    package["riskScore"] = json!(41);
    package["recommendedFixVersion"] = json!("1.3.1");
    package["relatedAdvisoryIds"] = json!(["GHSA-0001"]);
    package["reasons"] = json!([
        {"advisoryId": "GHSA-0001", "code": "advisory", "message": "m", "source": "bundle"},
    ]);
    vector
}

#[test]
fn feed_refresh_keeps_saved_approval_valid() {
    let saved = scored_vector();
    let mut refreshed = saved.clone();
    let package = &mut refreshed["request"]["evaluation"]["packages"][0];
    package["riskScore"] = json!(57);
    package["recommendedFixVersion"] = json!("1.4.0");
    package["reasons"] = json!([
        {"advisoryId": "GHSA-0001", "code": "advisory", "message": "stale bundle", "source": "bundle"},
        {"code": "cloud_validation_error", "message": "invalid reply", "source": "guard-cloud"},
    ]);
    let evaluation = &mut refreshed["request"]["evaluation"];
    evaluation["bundle_version"] = json!("b2");
    evaluation["policy_version"] = json!("p2");
    evaluation["reasons"] = json!([
        {"code": "cloud_timeout", "message": "Guard cloud evaluation timed out, so Guard fell back locally."},
        {"code": "advisory", "message": "reworded", "severity": "high"},
        {"code": "advisory", "message": "duplicate", "severity": "high"},
    ]);
    refreshed["request"]["feed_snapshot_hash"] = json!("refreshed-snapshot");

    let saved = context_token(&saved, "refresh-saved");
    let current = context_token(&refreshed, "refresh-current");
    assert_eq!(
        crate::context_digest::validate_context_tokens(&saved, &current),
        None
    );
}

/// A feed refresh that matches a new advisory, or a new rule, keeps a saved
/// approval: the advisory surfaces as a finding instead of a fresh prompt.
#[test]
fn a_new_advisory_or_rule_match_keeps_the_saved_approval() {
    let saved = scored_vector();
    let saved_token = context_token(&saved, "match-saved");

    let mut new_advisory = saved.clone();
    new_advisory["advisory_rows"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "GHSA-0002", "package_url": "pkg:npm/left-pad@1.3.0"}));
    let mut new_rule = saved.clone();
    new_rule["request"]["evaluation"]["matched_rule_id"] = json!("rule-2");
    let mut package_advisory = saved.clone();
    package_advisory["request"]["evaluation"]["packages"][0]["relatedAdvisoryIds"] =
        json!(["GHSA-0001", "GHSA-0002"]);
    let mut package_rule = saved.clone();
    package_rule["request"]["evaluation"]["packages"][0]["ruleId"] = json!("rule-2");

    for (name, changed) in [
        ("advisory", new_advisory),
        ("rule", new_rule),
        ("package-advisory", package_advisory),
        ("package-rule", package_rule),
    ] {
        let current = context_token(&changed, name);
        assert_eq!(
            crate::context_digest::validate_context_tokens(&saved_token, &current),
            None,
            "{name}"
        );
    }
}

/// A changed verdict still asks again. A blocking verdict never reaches reuse:
/// a saved approval cannot lower `block`.
#[test]
fn feed_changes_that_touch_the_verdict_still_require_reapproval() {
    let saved = scored_vector();
    let saved_token = context_token(&saved, "verdict-saved");

    let mut new_reason = saved.clone();
    new_reason["request"]["evaluation"]["reasons"]
        .as_array_mut()
        .unwrap()
        .push(json!({"code": "typosquat", "message": "m", "severity": "high"}));
    let mut package_verdict = saved.clone();
    package_verdict["request"]["evaluation"]["packages"][0]["decision"] = json!("block");
    let mut package_reason = saved.clone();
    package_reason["request"]["evaluation"]["packages"][0]["reasons"]
        .as_array_mut()
        .unwrap()
        .push(json!({"code": "malware", "message": "m", "source": "bundle"}));

    for (name, changed) in [
        ("reason", new_reason),
        ("package-verdict", package_verdict),
        ("package-reason", package_reason),
    ] {
        let current = context_token(&changed, name);
        assert_eq!(
            crate::context_digest::validate_context_tokens(&saved_token, &current).as_deref(),
            Some("approval_reuse_policy_changed"),
            "{name}"
        );
    }
}
