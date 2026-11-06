//! Parity of pure helpers, the containment contract and health gating with
//! vectors recorded from the original Python implementation.

use std::collections::BTreeMap;

use serde_json::Value;

use super::common::{canonical_bytes, clean_environment, file_sha256, framed_digest, normpath};
use super::contract::{Attestation, Backend, Input, Policy, Request};
use super::health::{combine_health, iso_utc, policy_contract_digest, HealthEvidence};
use super::pkg_json::version_spec_matches;
use super::runner_options::{bun_locked_version, vitest_result_arguments};
use super::vector_support::{fixture_of, section, strings, text, vectors, Workspace};
use crate::effect_decision::ProofRequirement;

#[test]
fn framed_digest_matches_python() {
    for case in section("framed") {
        assert_eq!(
            framed_digest(&case["payload"]).expect("framed"),
            text(case, "digest")
        );
    }
}

#[test]
fn normpath_matches_python() {
    for case in section("normpath") {
        assert_eq!(
            normpath(&text(case, "input")),
            text(case, "expected"),
            "{case}"
        );
    }
}

#[test]
fn clean_environment_matches_python() {
    for case in section("clean_environment") {
        let env: BTreeMap<String, String> = case["env"]
            .as_object()
            .expect("env")
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_owned()))
            .collect();
        let observed: Vec<Value> = clean_environment(&env)
            .into_iter()
            .map(|(key, value)| serde_json::json!([key, value]))
            .collect();
        assert_eq!(Value::Array(observed), case["expected"], "{case}");
    }
}

#[test]
fn version_spec_matches_python() {
    for case in section("version_spec") {
        let observed = version_spec_matches(
            case["spec"].as_str(),
            case["version"].as_str(),
            case["caret_pins_zero_major"] == Value::Bool(true),
        );
        assert_eq!(Value::Bool(observed), case["expected"], "{case}");
    }
}

#[test]
fn vitest_arguments_match_python() {
    for case in section("vitest_arguments") {
        let (files, valid) = vitest_result_arguments(&strings(&case["tail"]));
        assert_eq!(Value::Bool(valid), case["valid"], "{case}");
        assert_eq!(files, strings(&case["files"]), "{case}");
    }
}

#[test]
fn bun_locked_version_matches_python() {
    for case in section("bun_locked_version") {
        let package = text(case, "package");
        let (version, source_ok) = bun_locked_version(case["payload"].as_object(), &package);
        assert_eq!(version.as_deref(), case["version"].as_str(), "{case}");
        assert_eq!(Value::Bool(source_ok), case["source_ok"], "{case}");
    }
}

#[test]
fn iso_utc_matches_python() {
    for case in section("iso_utc") {
        let micros = case["micros"].as_i64().expect("micros");
        assert_eq!(iso_utc(micros), text(case, "iso"), "{case}");
    }
}

#[test]
fn policy_contract_digest_matches_python() {
    assert_eq!(
        policy_contract_digest(),
        text(&vectors()["contract"], "policy_contract_digest")
    );
}

#[test]
fn request_payloads_match_python() {
    for case in section_contract("requests") {
        let workspace = Workspace::with_fixture(fixture_of(case));
        let ws = workspace.text();
        let tag = |value: &str| format!("P:{}", workspace.templatize(value));
        let policy = Policy::new(&ws).expect("policy");
        assert_eq!(
            text(case, "policy_digest"),
            policy.digest_with(&tag).expect("policy digest")
        );
        let inputs: Vec<Input> = strings(&case["input_paths"])
            .iter()
            .map(|name| {
                let source = workspace.path.join(name);
                let digest = file_sha256(&source).expect("digest");
                Input::new(&source.to_string_lossy(), name, &digest).expect("input")
            })
            .collect();
        let mut argv = vec![workspace.path.join("tool").to_string_lossy().into_owned()];
        argv.extend(strings(&case["argv_tail"]));
        let environment: Vec<(String, String)> = case["environment"]
            .as_array()
            .expect("environment")
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap_or_default().to_owned(),
                    pair[1].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        let request = Request::new(
            &argv,
            &ws,
            &environment,
            policy,
            inputs,
            &"1".repeat(64),
            &"2".repeat(64),
            &text(case, "operation_id"),
        )
        .expect("request");
        let payload = request.payload(&tag).expect("payload");
        let observed = workspace.templatize(
            &String::from_utf8(canonical_bytes(&payload).expect("bytes")).expect("utf8"),
        );
        assert_eq!(
            observed,
            text(case, "binding_payload"),
            "{}",
            text(case, "id")
        );

        let attestation = Attestation::new(Backend::MacosSandbox, &"3".repeat(64), &request, None)
            .expect("attestation");
        let tagged = Attestation {
            request_digest: request
                .binding_digest_with(&tag)
                .expect("tagged request digest"),
            policy_digest: text(case, "policy_digest"),
            ..attestation.clone()
        };
        let proof_text =
            String::from_utf8(canonical_bytes(&tagged.bound_payload()).expect("bytes"))
                .expect("utf8");
        let template =
            text(case, "proof_payload").replace("{request_digest}", &tagged.request_digest);
        assert_eq!(proof_text, template, "{}", text(case, "id"));
        let proof = attestation
            .execution_bound_proof(&request, &[ProofRequirement::ContainmentIdentity])
            .expect("proof");
        assert_eq!(proof.route.as_str(), text(case, "route"));
        let satisfied: Vec<&str> = proof
            .satisfied_requirements
            .iter()
            .map(|item| item.as_str())
            .collect();
        assert_eq!(Value::from(satisfied), case["satisfied"]);
    }
}

fn section_contract(name: &str) -> &'static [Value] {
    vectors()["contract"][name]
        .as_array()
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn backend_of(name: &str) -> Backend {
    match name {
        "macos-sandbox" => Backend::MacosSandbox,
        "linux-bwrap" => Backend::LinuxBwrap,
        "unsupported" => Backend::Unsupported,
        other => panic!("unknown backend {other}"),
    }
}

#[test]
fn health_evidence_matches_python() {
    for case in section_contract("health") {
        let mut health = HealthEvidence::new(
            backend_of(&text(case, "backend")),
            text(case, "backend_digest"),
            &text(case, "daemon_fingerprint"),
            case["probe_micros"].as_i64().expect("probe"),
            case["probe_enforced"] == Value::Bool(true),
        );
        health.runtime_fingerprint = text(case, "runtime_fingerprint");
        health.policy_contract_digest = text(case, "policy_contract_digest");
        health.containment_schema_version = text(case, "containment_schema_version");
        health.policy_version = text(case, "policy_version");
        health.effect_contract_schema_version = text(case, "effect_contract_schema_version");
        health.effect_decision_schema_version = text(case, "effect_decision_schema_version");
        let id = text(case, "id");
        assert_eq!(health.to_value()["probe_at"], case["probe_at"], "{id}");
        let errors = health.compatibility_errors(
            case["now_micros"].as_i64().expect("now"),
            Some(&text(case, "runtime_arg")),
        );
        assert_eq!(Value::from(errors), case["errors"], "{id}");
        let digest = health.binding_digest().expect("binding");
        assert_eq!(digest, text(case, "binding_digest"), "{id}");
        assert_eq!(
            combine_health(&"8".repeat(64), &health).expect("combined"),
            text(case, "combined"),
            "{id}"
        );
    }
}
