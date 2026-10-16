//! What the relay's package evaluation assembles and what it refuses.
//!
//! The resident is scripted and the network is never reached: the policy these
//! cases evaluate under refuses every destination, or does not resolve at all.

use super::*;

use std::fs;
use std::path::Path;

use guard_command::package_intent_parser::parse_package_intent;
use guard_contracts::{
    EgressNeedV1, EgressRequiredV1, SupplyChainEvalResultV1, EGRESS_REQUIRED_CODE,
    PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Value};
use tempfile::TempDir;

use crate::managed_policy::POLICY_SCHEMA_VERSION;
use crate::managed_policy_load::MachineSystem;

/// `_EVAL_MAX_REQUEST_BYTES`, as the round loop digests a request under.
const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

fn facts<'a>(home: &'a str, workspace: Option<&'a str>) -> PackageEvalFacts<'a> {
    PackageEvalFacts {
        guard_home: home,
        workspace,
        harness: "claude-code",
        source_scope: "project",
        config_path: "/home/dev/.mcp.json",
    }
}

fn intent(command: &str) -> PackageIntent {
    parse_package_intent(command, None, None, None, None).expect("the command carries an intent")
}

/// An administrator's profile read without the machine ownership walk, which is
/// how `policy_path=` reads one.
fn explicit(path: &Path) -> ManagedPolicySource {
    ManagedPolicySource {
        system: MachineSystem::Other,
        policy_path: Some(path.to_path_buf()),
        write_cache: false,
        machine_root: None,
    }
}

/// `proxyMode: "none"` throughout, so resolving a policy never reads the
/// machine's own proxy configuration: these cases are about the evaluation.
fn profile(root: &TempDir, allow_public_registries: bool) -> ManagedPolicySource {
    let path = root.path().join("policy.json");
    let document = json!({
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce"},
        "lockedSettings": ["mode"],
        "network": {
            "proxyMode": "none",
            "allowPublicRegistries": allow_public_registries,
        },
    });
    fs::write(&path, serde_json::to_vec(&document).expect("document")).expect("write");
    explicit(&path)
}

/// A machine whose administrator installed a profile this runtime cannot read.
fn unreadable_profile(root: &TempDir) -> ManagedPolicySource {
    let path = root.path().join("policy.json");
    fs::write(&path, b"{").expect("write");
    explicit(&path)
}

fn complete_payload() -> Value {
    json!({
        "decision": "allow",
        "policy_action": "allow",
        "enforcement": "enforced",
        "entitlement_state": "entitled",
        "cache_status": "miss",
        "package_intent_hash": "sha256:abc",
        "policy_version": "1",
        "risk_summary": "none",
        "reasons": [],
        "packages": [],
        "user_copy": {"title": "t", "summary": "s", "harness_message": "h"},
    })
}

fn need(url: &str) -> EgressNeedV1 {
    EgressNeedV1 {
        class: "registry_metadata".to_owned(),
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: Default::default(),
        body: None,
        body_sha256: String::new(),
        occurrence: 1,
        timeout_seconds: 1.0,
        max_redirects: 0,
        max_response_bytes: 1024,
        delay_seconds: 0.0,
        inspect: None,
    }
}

/// Answers each round from a script, bound to the request it answers.
struct ScriptedResident {
    answers: Vec<(&'static str, Option<Value>)>,
    seen: Vec<SupplyChainEvalRequestV1>,
}

impl ScriptedResident {
    fn new(answers: Vec<(&'static str, Option<Value>)>) -> Self {
        Self {
            answers,
            seen: Vec::new(),
        }
    }

    fn verdict() -> Self {
        Self::new(vec![("ok", Some(complete_payload()))])
    }
}

impl SupplyChainEvalTransport for ScriptedResident {
    fn evaluate(&mut self, request: &SupplyChainEvalRequestV1) -> Option<SupplyChainEvalResultV1> {
        self.seen.push(request.clone());
        let (code, payload) = self.answers.remove(0);
        let request_sha256 =
            crate::package_authority_op::request_digest_with_limit(request, MAX_REQUEST_BYTES)
                .expect("digest");
        Some(SupplyChainEvalResultV1 {
            schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
            request_id: request.request_id.clone(),
            request_sha256,
            status: "ok".to_owned(),
            code: code.to_owned(),
            payload,
        })
    }
}

#[test]
fn the_request_names_the_home_the_store_and_the_parsed_intent() {
    let request = package_eval_request(
        &facts("/home/dev/.hol-guard", Some("/home/dev/app")),
        &intent("npm install left-pad"),
        false,
    );

    assert_eq!(request.schema, PACKAGE_AUTHORITY_REQUEST_SCHEMA);
    assert_eq!(request.guard_home, "/home/dev/.hol-guard");
    let store = Path::new("/home/dev/.hol-guard").join(STORE_FILE);
    assert_eq!(
        Path::new(&request.store_path),
        store.as_path(),
        "the store is named beside the home, in the host's own spelling"
    );
    assert_eq!(request.workspace_dir.as_deref(), Some("/home/dev/app"));
    assert_eq!(
        request
            .artifact
            .get("artifact_type")
            .and_then(Value::as_str),
        Some("package_request")
    );
    let artifact_id = request
        .artifact
        .get("artifact_id")
        .and_then(Value::as_str)
        .expect("artifact id");
    assert!(
        artifact_id.starts_with("claude-code:project:package-request:"),
        "{artifact_id}"
    );
    // The round fields are the loop's to set.
    assert!(request.request_id.is_empty());
    assert!(request.now.is_none());
    assert!(request.egress_supplied.is_none());
    assert!(request.saved_policy_probe.is_none());
}

#[test]
fn a_relay_without_a_workspace_evaluates_a_request_bound_to_none() {
    let request = package_eval_request(
        &facts("/home/dev/.hol-guard", None),
        &intent("pip install requests"),
        false,
    );

    // Omitted rather than null: the resident digests its typed request.
    assert!(request.workspace_dir.is_none());
}

#[test]
fn the_relay_retains_no_archive_blob() {
    let request = package_eval_request(
        &facts("/home/dev/.hol-guard", Some("/home/dev/app")),
        &intent("npm install left-pad"),
        true,
    );

    assert!(
        request.external_archive_network_authorized,
        "a post-claim evaluation may download an archive"
    );
    assert!(
        !request.retain_external_archive_blob,
        "the evidence a retained blob carries is not this caller's to keep"
    );
}

#[test]
fn an_evaluation_the_resident_answers_from_its_cache_settles() {
    let root = TempDir::new().expect("tempdir");
    let mut resident = ScriptedResident::verdict();

    let settled = evaluate_package_request(
        &facts("/home/dev/.hol-guard", Some("/home/dev/app")),
        &intent("npm install left-pad"),
        false,
        &profile(&root, true),
        &mut resident,
    )
    .expect("the resident answered with a verdict");

    assert_eq!(
        settled.payload.get("decision").and_then(Value::as_str),
        Some("allow")
    );
    assert!(settled.retained_archives.is_empty());
    assert_eq!(resident.seen.len(), 1, "no round needed the network");
}

#[test]
fn a_round_that_needs_the_network_is_performed_under_the_machines_policy() {
    let root = TempDir::new().expect("tempdir");
    let needs = vec![need("https://registry.npmjs.org/left-pad")];
    let mut resident = ScriptedResident::new(vec![
        (
            EGRESS_REQUIRED_CODE,
            Some(serde_json::to_value(EgressRequiredV1 { needs }).expect("needs")),
        ),
        ("ok", Some(complete_payload())),
    ]);

    let settled = evaluate_package_request(
        &facts("/home/dev/.hol-guard", Some("/home/dev/app")),
        &intent("npm install left-pad"),
        false,
        &profile(&root, false),
        &mut resident,
    )
    .expect("the replayed outcome settled the evaluation");

    assert_eq!(
        settled.payload.get("decision").and_then(Value::as_str),
        Some("allow")
    );
    let replayed = resident.seen[1]
        .egress_supplied
        .as_ref()
        .expect("the second round carries what the caller performed");
    assert_eq!(replayed.len(), 1, "the refusal is an outcome, not a gap");
    assert!(
        !resident.seen[1]
            .egress_spool_dir
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "the round that needed the network named its spool"
    );
}

#[test]
fn a_policy_this_caller_cannot_honour_does_not_settle_a_round_that_needs_the_network() {
    let root = TempDir::new().expect("tempdir");
    let needs = vec![need("https://registry.npmjs.org/left-pad")];
    let mut resident = ScriptedResident::new(vec![(
        EGRESS_REQUIRED_CODE,
        Some(serde_json::to_value(EgressRequiredV1 { needs }).expect("needs")),
    )]);

    let refused = evaluate_package_request(
        &facts("/home/dev/.hol-guard", Some("/home/dev/app")),
        &intent("npm install left-pad"),
        false,
        &unreadable_profile(&root),
        &mut resident,
    )
    .expect_err("an unreadable profile exchanges nothing");

    assert_eq!(
        refused.reason(),
        CallerEgressFulfilment::policy_unhonoured(),
        "the caller refused, rather than exchanging under default trust"
    );
}

#[test]
fn a_machine_whose_registry_policy_is_unread_does_not_settle_a_round_that_needs_the_network() {
    // Windows keeps the administrator's policy in the registry, which this
    // runtime does not read, so a proxy, CA, or public-registry rule set there
    // is invisible to this caller. The exchange is refused rather than
    // performed under the unmanaged default.
    let needs = vec![need("https://registry.npmjs.org/left-pad")];
    let mut resident = ScriptedResident::new(vec![(
        EGRESS_REQUIRED_CODE,
        Some(serde_json::to_value(EgressRequiredV1 { needs }).expect("needs")),
    )]);
    let registry = ManagedPolicySource {
        system: MachineSystem::Windows,
        policy_path: None,
        write_cache: false,
        machine_root: None,
    };

    let refused = evaluate_package_request(
        &facts("/home/dev/.hol-guard", Some("/home/dev/app")),
        &intent("npm install left-pad"),
        false,
        &registry,
        &mut resident,
    )
    .expect_err("an unread registry authority exchanges nothing");

    assert_eq!(
        refused.reason(),
        CallerEgressFulfilment::policy_unhonoured(),
        "the caller refused, rather than exchanging under default trust"
    );
}

#[test]
fn an_answer_asking_for_a_saved_policy_row_is_not_a_verdict() {
    let root = TempDir::new().expect("tempdir");
    let mut resident = ScriptedResident::new(vec![(
        "saved_policy_probe_required",
        Some(json!({"error": "cloud_validation_cached"})),
    )]);

    let refused = evaluate_package_request(
        &facts("/home/dev/.hol-guard", Some("/home/dev/app")),
        &intent("npm install left-pad"),
        false,
        &profile(&root, true),
        &mut resident,
    )
    .expect_err("this caller cannot hydrate the row the resident asked for");

    assert_eq!(refused.reason(), "not_a_verdict");
}
