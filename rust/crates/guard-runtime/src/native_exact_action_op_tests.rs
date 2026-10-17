//! Parity vectors recorded from the retired Python implementation.
//!
//! Each case carries a file tree, the wire request and the answer the Python
//! proofs gave on the same tree. The two machine-dependent engines (launch
//! identity, package intent) are replaced by the deterministic fakes the
//! recorder used, so only the proofs under test can differ.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use guard_contracts::{NativeExactActionPayloadV1, NativeExactActionRequestV1};
use serde_json::{json, Value};

use super::context::{Engines, EvidenceFile, LocalExecution};
use super::{decide, token};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/native_exact_action_vectors.json.gz");

struct Fake {
    #[cfg_attr(windows, allow(dead_code))]
    root: String,
    intent: Value,
}

fn evidence(value: &Value) -> Option<EvidenceFile> {
    let object = value.as_object()?;
    let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_owned);
    Some(EvidenceFile {
        path: text("path")?,
        resolved_path: text("resolved_path"),
        status: text("status")?,
        content_hash: text("content_hash"),
    })
}

fn files(value: &Value) -> Vec<EvidenceFile> {
    value
        .as_array()
        .map(|items| items.iter().filter_map(evidence).collect())
        .unwrap_or_default()
}

impl Engines for Fake {
    fn launch_identity(
        &self,
        executable: &str,
        args: &[String],
        cwd: &str,
        home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Value {
        json!({"fake_launch": true, "executable": executable, "args": args, "cwd": cwd, "home": home})
    }

    fn launch_reusable(&self, identity: &Value) -> bool {
        !identity["executable"]
            .as_str()
            .unwrap_or("")
            .contains("unreusable")
    }

    fn system_git_config(&self) -> String {
        format!("{}/etc/gitconfig", self.root)
    }

    fn local_executions(
        &self,
        _command: &str,
        _cwd: &str,
        _home: Option<&str>,
        _env: &BTreeMap<String, String>,
    ) -> Option<Vec<LocalExecution>> {
        let executions = self.intent.as_array()?;
        Some(
            executions
                .iter()
                .map(|item| LocalExecution {
                    local_executable: evidence(&item["local_executable"]),
                    manager: evidence(&item["manager"]),
                    manager_is_guard_shim: item["manager_is_guard_shim"].as_bool().unwrap_or(false),
                    package_name: item["package_name"].as_str().map(str::to_owned),
                    executable_name: item["executable_name"].as_str().map(str::to_owned),
                    manifests: files(&item["manifests"]),
                    lockfiles: files(&item["lockfiles"]),
                })
                .collect(),
        )
    }
}

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "eav-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path.canonicalize().unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn materialize(root: &Path, tree: &serde_json::Map<String, Value>) {
    let mut entries: Vec<(&String, &Value)> =
        tree.iter().filter(|(_, spec)| !spec.is_null()).collect();
    entries.sort_by_key(|(path, _)| path.matches('/').count());
    let mut links = Vec::new();
    for (relative, spec) in entries {
        let path = root.join(relative);
        if let Some(target) = spec.get("symlink").and_then(Value::as_str) {
            links.push((path, target.to_owned()));
            continue;
        }
        if spec.get("dir").is_some() {
            std::fs::create_dir_all(&path).unwrap();
            continue;
        }
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = match spec.get("fill").and_then(Value::as_u64) {
            Some(count) => spec["char"]
                .as_str()
                .unwrap_or("x")
                .repeat(count as usize)
                .into_bytes(),
            None => spec.as_str().unwrap().as_bytes().to_vec(),
        };
        std::fs::write(&path, bytes).unwrap();
    }
    for (path, target) in links {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, path).unwrap();
        #[cfg(not(unix))]
        let _ = (path, target);
    }
}

fn load() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let mut document: Value = serde_json::from_str(&text).unwrap();
    match document["cases"].take() {
        Value::Array(cases) => cases,
        _ => panic!("fixture has no cases"),
    }
}

/// A recorded git config digest carries the pairs it hashed, because they hold
/// absolute paths of the machine that recorded it (and config files that name
/// them, kept as text).
fn config_digest(preimage: &str) -> String {
    let mut pairs: Value = serde_json::from_str(preimage).unwrap();
    for pair in pairs.as_array_mut().unwrap() {
        if let Some(text) = pair[1]
            .as_str()
            .and_then(|text| text.strip_prefix("{FILE_SHA}"))
        {
            pair[1] = Value::String(super::fs_path::sha256_hex(text.as_bytes()));
        }
    }
    let mut encoded = Vec::new();
    guard_contracts::write_canonical_json(&pairs, &mut encoded).unwrap();
    super::fs_path::sha256_hex(&encoded)
}

fn resolve_digests(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(preimage) = text.strip_prefix("{GIT_CONFIG_DIGEST}") {
                *text = config_digest(preimage);
            }
        }
        Value::Array(items) => items.iter_mut().for_each(resolve_digests),
        Value::Object(map) => map.values_mut().for_each(resolve_digests),
        _ => {}
    }
}

fn clip(value: &Value) -> String {
    value.to_string().chars().take(140).collect()
}

fn first_difference(got: &Value, want: &Value) -> String {
    if let (Value::Object(left), Value::Object(right)) = (got, want) {
        for key in left.keys().chain(right.keys()) {
            if left.get(key) != right.get(key) {
                return format!(
                    ".{key}{}",
                    first_difference(
                        left.get(key).unwrap_or(&Value::Null),
                        right.get(key).unwrap_or(&Value::Null)
                    )
                );
            }
        }
    }
    format!(": {} != {}", clip(got), clip(want))
}

fn run_case(case: &Value) -> Result<(), String> {
    let scratch = Scratch::new();
    let root = scratch.0.to_str().unwrap().to_owned();
    let concrete: Value = serde_json::from_str(
        &case
            .to_string()
            .replace("{ROOT}", &root.replace('\\', "\\\\")),
    )
    .unwrap();
    materialize(&scratch.0, concrete["tree"].as_object().unwrap());
    let request: NativeExactActionRequestV1 =
        serde_json::from_value(concrete["request"].clone()).unwrap();
    let engines = Fake {
        root,
        intent: concrete["intent"].clone(),
    };
    let expected = &concrete["expected"];
    let payload = decide(&request, &engines).map_err(|code| format!("error {code}"))?;
    match payload {
        NativeExactActionPayloadV1::ReviewBinding { binding } => {
            let want = expected["binding"].as_str().map(str::to_owned);
            (binding == want)
                .then_some(())
                .ok_or(format!("binding {binding:?} != {want:?}"))
        }
        NativeExactActionPayloadV1::ExactAction {
            token: minted,
            once_only_reason,
        } => {
            let want_reason = expected["once_only_reason"].as_str().map(str::to_owned);
            if once_only_reason != want_reason
                || minted.is_some() != expected["token_present"].as_bool().unwrap()
            {
                return Err(format!(
                    "reason {once_only_reason:?} != {want_reason:?} (token {})",
                    minted.is_some()
                ));
            }
            if minted.is_none() {
                return Ok(());
            }
            let mut wanted = expected["components"].clone();
            resolve_digests(&mut wanted);
            let deadline = Instant::now() + Duration::from_secs(20);
            let components = token::exact_action_components(&request.query, deadline, &engines)
                .map_err(|reason| reason.to_owned())?;
            for (name, got) in [
                ("identity", &components.identity),
                ("content", &components.content),
                ("capabilities", &components.capabilities),
                ("policy", &components.policy),
                ("sandbox", &components.sandbox),
            ] {
                if got != &wanted[name] {
                    return Err(format!("{name}{}", first_difference(got, &wanted[name])));
                }
            }
            Ok(())
        }
    }
}

/// The recorded trees and requests are POSIX: `:`-separated `PATH`s, `/`-rooted
/// paths and symlinks. The proofs model POSIX path semantics, so on Windows
/// every launch stays one-time (`a_windows_launch_stays_a_one_time_decision`).
#[cfg_attr(
    not(unix),
    ignore = "POSIX-recorded vectors; Windows launches fail closed to one-time decisions"
)]
#[test]
fn matches_vectors_recorded_from_python() {
    let cases = load();
    assert!(cases.len() > 600, "fixture shrank to {}", cases.len());
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|case| {
            run_case(case)
                .err()
                .map(|message| format!("{}: {message}", case["name"].as_str().unwrap()))
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} vectors differ:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(25)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// A review on Windows never mints a persistent token: the identity proofs
/// bind `/`-rooted spellings, so the action stays a one-time decision.
#[cfg(windows)]
#[test]
fn a_windows_launch_stays_a_one_time_decision() {
    let case = load()
        .into_iter()
        .find(|case| case["name"] == "gate_baseline")
        .unwrap();
    assert_eq!(case["expected"]["token_present"], true);
    let scratch = Scratch::new();
    let root = scratch.0.to_str().unwrap().trim_start_matches(r"\\?\");
    let concrete: Value = serde_json::from_str(
        &case
            .to_string()
            .replace("{ROOT}", &root.replace('\\', "\\\\")),
    )
    .unwrap();
    materialize(&scratch.0, concrete["tree"].as_object().unwrap());
    let request: NativeExactActionRequestV1 =
        serde_json::from_value(concrete["request"].clone()).unwrap();
    let engines = Fake {
        root: root.to_owned(),
        intent: concrete["intent"].clone(),
    };
    let NativeExactActionPayloadV1::ExactAction {
        token,
        once_only_reason,
    } = decide(&request, &engines).unwrap()
    else {
        panic!("an exact-action query answers with an exact action");
    };
    assert!(token.is_none());
    assert_eq!(once_only_reason.as_deref(), Some("unproven_launch"));
}

fn resident(request: &Value) -> Value {
    let wrapped = json!({"operation": "native_exact_action", "request": request});
    let bytes =
        crate::resident_protocol::evaluate_resident_bytes(wrapped.to_string().as_bytes(), None)
            .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn binding_request(schema: &str) -> Value {
    json!({
        "schema": schema,
        "request_id": "req-binding",
        "query": {
            "kind": "review_binding", "harness": "codex", "command": "cat notes", "workspace_bound": true,
            "facts": {"decision": "ask", "minimum_action": "review", "policy_action": "review", "reason_code": "r"},
            "receipt": {
                "schema": "guard-native-hook-decision-receipt.v1", "version": 1, "authority": "rust",
                "harness": "codex", "event_name": "PreToolUse", "workspace_bound": true,
                "request_digest": "ab".repeat(32), "review_anchor_digest": "cd".repeat(32),
                "decision": "ask", "policy_action": "review", "reason_code": "r"
            },
            "policy_binding": {"state": "unbound"}
        }
    })
}

#[test]
fn wire_reply_is_bound_to_the_request() {
    let reply = resident(&binding_request("guard-native-exact-action-request.v1"));
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["schema"], "guard-native-exact-action-result.v1");
    assert_eq!(reply["request_id"], "req-binding");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let binding = reply["payload"]["binding"].as_str().unwrap();
    assert_eq!(
        binding,
        format!("native-review-v4:{}:ask:review:review:r", "cd".repeat(32))
    );
}

fn binding_for(receipt_fields: Value, policy_binding: Value) -> Option<String> {
    let mut request = binding_request("guard-native-exact-action-request.v1");
    for (key, value) in receipt_fields.as_object().unwrap() {
        request["query"]["receipt"][key] = value.clone();
    }
    request["query"]["policy_binding"] = policy_binding;
    let reply = resident(&request);
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"]["binding"].as_str().map(str::to_owned)
}

/// The retry the user already approved must still match after the publisher
/// republishes the snapshot. `request_digest` folds in the generation and the
/// snapshot digest, which both move on a republish that decided nothing; the
/// anchor does not, so the binding stays put.
#[test]
fn wire_reply_binding_survives_a_republished_request_digest() {
    let anchor = "cd".repeat(32);
    let before = binding_for(
        json!({"request_digest": "ab".repeat(32)}),
        json!({"state": "unbound"}),
    );
    let after = binding_for(
        json!({"request_digest": "ef".repeat(32)}),
        json!({"state": "unbound"}),
    );
    assert_eq!(before, after);
    assert_eq!(
        before.as_deref(),
        Some(format!("native-review-v4:{anchor}:ask:review:review:r").as_str())
    );
    let other_action = binding_for(
        json!({"review_anchor_digest": "12".repeat(32)}),
        json!({"state": "unbound"}),
    );
    assert_ne!(before, other_action);
}

/// An anchor that is not a digest produces no binding at all, so the retry is
/// reviewed again rather than matched on evidence the runtime never proved.
#[test]
fn wire_reply_is_unbound_by_a_malformed_review_anchor() {
    for anchor in [
        json!("short"),
        json!("not-a-digest"),
        json!("AB".repeat(32)),
        json!(7),
    ] {
        assert_eq!(
            binding_for(
                json!({"review_anchor_digest": anchor}),
                json!({"state": "unbound"})
            ),
            None
        );
    }
}

/// A receipt from a runtime that anchors neither keeps the request digest: the
/// republish still moves the binding, but the review is queued as before.
#[test]
fn wire_reply_falls_back_to_the_request_digest_without_an_anchor() {
    let mut request = binding_request("guard-native-exact-action-request.v1");
    request["query"]["receipt"]
        .as_object_mut()
        .unwrap()
        .remove("review_anchor_digest");
    let binding = resident(&request)["payload"]["binding"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        binding,
        format!("native-review-v4:{}:ask:review:review:r", "ab".repeat(32))
    );
}

/// The execution intent never anchors a binding: it drops `guard_home`,
/// `home_dir` and `source_ref_external_allowed`, so an approval anchored to it
/// could be consumed under another guard home. With an anchor beside it the
/// anchor wins; alone it is ignored and the request digest is kept.
#[test]
fn the_execution_intent_never_anchors_the_wire_reply() {
    let beside_the_anchor = binding_for(
        json!({"execution_intent_digest": "12".repeat(32)}),
        json!({"state": "unbound"}),
    );
    assert_eq!(
        beside_the_anchor.as_deref(),
        Some(format!("native-review-v4:{}:ask:review:review:r", "cd".repeat(32)).as_str())
    );
    let mut request = binding_request("guard-native-exact-action-request.v1");
    let receipt = request["query"]["receipt"].as_object_mut().unwrap();
    receipt.remove("review_anchor_digest");
    receipt.insert("execution_intent_digest".into(), json!("12".repeat(32)));
    let intent_only = resident(&request)["payload"]["binding"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        intent_only,
        format!("native-review-v4:{}:ask:review:review:r", "ab".repeat(32))
    );
}

/// A policy binding still sent in the v1 shape keeps its `policy_digest` out
/// of the suffix, while the rules it carries still change the binding.
#[test]
fn the_policy_suffix_ignores_the_snapshot_digest_but_not_the_rules() {
    let bound = |policy_digest: &str, rule_digest: &str| {
        json!({"state": "bound", "value": {
            "schema": "guard-native-review-policy-binding.v1",
            "policy_digest": policy_digest,
            "rule_digest": rule_digest,
            "runtime_identity": "runtime-1",
            "command_extensions": {"uncertainty_count": 0}
        }})
    };
    let first = binding_for(json!({}), bound(&"1".repeat(64), &"a".repeat(64)));
    let republished = binding_for(json!({}), bound(&"2".repeat(64), &"a".repeat(64)));
    let new_rules = binding_for(json!({}), bound(&"2".repeat(64), &"b".repeat(64)));
    assert!(first.is_some());
    assert_eq!(first, republished);
    assert_ne!(first, new_rules);
}

#[test]
fn wire_schema_mismatch_is_an_error_without_payload() {
    let reply = resident(&binding_request("guard-native-exact-action-request.v0"));
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_exact_action_schema_mismatch");
    assert!(reply["payload"].is_null());
}

#[test]
fn wire_exact_action_with_real_engines_answers_a_domain_outcome() {
    let scratch = Scratch::new();
    let root = scratch.0.to_str().unwrap();
    let request = json!({
        "schema": "guard-native-exact-action-request.v1",
        "request_id": "req-exact",
        "query": {
            "kind": "exact_action", "harness": "codex", "tool_name": "Bash", "command": "echo hi",
            "tool_input": [["command", "echo hi"]], "payload_cwd": root, "workspace": root, "home_dir": root,
            "environment": {"PATH": "/usr/bin:/bin"},
            "facts": {"decision": "ask", "minimum_action": "review", "policy_action": "review", "reason_code": "first_seen", "action_type": "shell"},
            "policy_binding": {"state": "unbound"},
            "extension_control_digest": "e".repeat(64), "budget_ms": 20000
        }
    });
    let reply = resident(&request);
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["payload"]["kind"], "exact_action");
    assert_eq!(reply["payload"]["once_only_reason"], "unproven_launch");
    assert!(reply["payload"]["token"].is_null());
}
