//! Runtime advisories reach matching only from a bundle that verifies.

use std::sync::OnceLock;

use guard_command::supply_chain_bundle::canonical_supply_chain_bundle_payload;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::pss::BlindedSigningKey;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::runtime_identity::run_command;

const VECTOR: &str =
    include_str!("../../../../tests/fixtures/supply-chain-bundle-producer-vector.v1.json");
const WORKSPACE: &str = "11111111-1111-4111-8111-111111111111";

fn signing_key() -> &'static RsaPrivateKey {
    static KEY: OnceLock<RsaPrivateKey> = OnceLock::new();
    KEY.get_or_init(|| RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("key"))
}

fn vector() -> Value {
    serde_json::from_str(VECTOR).expect("vector parses")
}

fn now() -> f64 {
    vector()["verify_at_epoch_seconds"]
        .as_f64()
        .expect("verify time")
}

fn node_rule() -> Value {
    json!({
        "advisoryId": "CVE-2026-111497",
        "aliases": [],
        "backportBuildIds": [],
        "includePrerelease": false,
        "knownExploited": false,
        "normalizedSeverity": "high",
        "ranges": [
            {"introduced": "11.7.0", "fixed": "22.23.4", "lastAffected": null},
            {"introduced": "23.0.0", "fixed": "24.22.1", "lastAffected": null}
        ],
        "releaseLines": ["22", "24"],
        "sourceKey": "vendor-advisory",
        "summary": "Fixture runtime advisory.",
        "target": {
            "kind": "runtime",
            "family": "node",
            "vendor": "nodejs.org",
            "component": null,
            "platforms": [{"os": "*", "arch": "*"}],
            "versionScheme": "semver"
        },
        "title": "Node.js fixture advisory"
    })
}

/// Re-sign the producer vector with `section` placed in the signed bundle.
fn signed_response(section: Option<Value>) -> Value {
    let mut response = vector()["response"].clone();
    if let Some(section) = section {
        response["bundle"]["runtimeAdvisories"] = section;
    }
    let key = signing_key();
    let pem = key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("pem");
    let key_id = response["bundle"]["keyId"].clone();
    response["verificationKeys"] = json!([{
        "fingerprintSha256": hex::encode(Sha256::digest(pem.trim().as_bytes())),
        "keyId": key_id,
        "publicKeyPem": pem,
        "state": "active",
        "validUntil": null
    }]);
    resign(&mut response);
    response
}

fn resign(response: &mut Value) {
    let canonical =
        canonical_supply_chain_bundle_payload(response["bundle"].as_object().expect("bundle"));
    response["payloadHash"] = json!(hex::encode(Sha256::digest(&canonical)));
    let key = signing_key();
    let encoded_len = (key.n().bits() - 1).div_ceil(8);
    let salt_len = encoded_len - 32 - 2;
    let signer = BlindedSigningKey::<Sha256>::new_with_salt_len(key.clone(), salt_len);
    let signature = signer.sign_with_rng(&mut rsa::rand_core::OsRng, &canonical);
    response["signature"] = json!(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        signature.to_bytes()
    ));
}

fn section(entries: Vec<Value>) -> Value {
    json!({"schemaVersion": "runtime-advisories.v1", "rulesetVersion": "2026-10-25.1", "entries": entries})
}

fn node_artifact(version: &str, os: &str) -> Value {
    json!({
        "artifact_id": "node-1",
        "family": "node",
        "vendor": "nodejs.org",
        "version": version,
        "build_id": null,
        "os": os,
        "arch": "arm64",
        "executable_sha256": null,
        "component_identity_sha256": null,
        "identity_assurance": "self_reported"
    })
}

fn assess(artifact: Value, cached_bundle: Value) -> Value {
    let request = json!({"artifacts": [artifact], "cached_bundle": cached_bundle});
    let reply = run_command(&serde_json::to_vec(&request).expect("request")).expect("reply");
    assert_eq!(reply["ok"], json!(true), "{reply}");
    reply["result"].clone()
}

fn cached(response: Value) -> Value {
    json!({"response": response, "workspace_id": WORKSPACE, "now": now()})
}

fn match_of(result: &Value) -> (Value, Value) {
    let found = &result["artifacts"][0]["matches"][0];
    (found["status"].clone(), found["reason"].clone())
}

#[test]
fn verified_bundle_rule_flags_an_affected_runtime() {
    let result = assess(
        node_artifact("22.12.0", "macos"),
        cached(signed_response(Some(section(vec![node_rule()])))),
    );
    assert_eq!(result["advisory_source"]["state"], json!("verified"));
    assert_eq!(result["advisory_source"]["entries"], json!(1));
    assert_eq!(match_of(&result), (json!("affected"), json!("in_range")));
    let advisory = &result["advisories"][0];
    assert_eq!(advisory["severity"], json!("high"));
    assert_eq!(advisory["title"], json!("Node.js fixture advisory"));
}

#[test]
fn fixed_runtime_is_not_flagged_by_a_bundle_rule() {
    let result = assess(
        node_artifact("22.23.4", "linux"),
        cached(signed_response(Some(section(vec![node_rule()])))),
    );
    assert_ne!(match_of(&result).0, json!("affected"));
}

#[test]
fn tampered_bundle_supplies_no_advisories() {
    let mut response = signed_response(Some(section(vec![node_rule()])));
    response["bundle"]["runtimeAdvisories"]["entries"][0]["ranges"][0]["fixed"] = json!("99.0.0");
    let result = assess(node_artifact("22.12.0", "macos"), cached(response));
    assert_eq!(result["advisory_source"]["state"], json!("invalid"));
    assert_eq!(
        result["advisory_source"]["reason"],
        json!("payload_hash_mismatch")
    );
    assert_eq!(result["advisories"], json!([]));
}

#[test]
fn bad_signature_supplies_no_advisories() {
    let mut response = signed_response(Some(section(vec![node_rule()])));
    response["bundle"]["runtimeAdvisories"]["rulesetVersion"] = json!("forged");
    let canonical =
        canonical_supply_chain_bundle_payload(response["bundle"].as_object().expect("bundle"));
    response["payloadHash"] = json!(hex::encode(Sha256::digest(&canonical)));
    let result = assess(node_artifact("22.12.0", "macos"), cached(response));
    assert_eq!(
        result["advisory_source"]["reason"],
        json!("signature_invalid")
    );
    assert_eq!(result["advisories"], json!([]));
}

#[test]
fn another_workspaces_bundle_supplies_no_advisories() {
    let mut input = cached(signed_response(Some(section(vec![node_rule()]))));
    input["workspace_id"] = json!("22222222-2222-4222-8222-222222222222");
    let result = assess(node_artifact("22.12.0", "macos"), input);
    assert_eq!(result["advisory_source"]["state"], json!("invalid"));
    assert_eq!(result["advisory_source"]["reason"], json!("scope_rejected"));
}

#[test]
fn expired_bundle_is_stale_and_supplies_no_advisories() {
    let mut input = cached(signed_response(Some(section(vec![node_rule()]))));
    input["now"] = json!(now() + 400_000_000.0);
    let result = assess(node_artifact("22.12.0", "macos"), input);
    assert_eq!(result["advisory_source"]["state"], json!("stale"));
    assert_eq!(result["advisories"], json!([]));
}

#[test]
fn bundle_without_the_section_or_with_a_newer_schema_supplies_nothing() {
    let absent = assess(
        node_artifact("22.12.0", "macos"),
        cached(signed_response(None)),
    );
    assert_eq!(absent["advisory_source"]["state"], json!("verified"));
    assert_eq!(absent["advisory_source"]["reason"], json!("section_absent"));
    let mut newer = section(vec![node_rule()]);
    newer["schemaVersion"] = json!("runtime-advisories.v2");
    let unsupported = assess(
        node_artifact("22.12.0", "macos"),
        cached(signed_response(Some(newer))),
    );
    assert_eq!(
        unsupported["advisory_source"]["reason"],
        json!("schema_unsupported")
    );
    assert_eq!(unsupported["advisories"], json!([]));
}

#[test]
fn unreadable_entries_are_skipped_not_fatal() {
    let mut unknown_kind = node_rule();
    unknown_kind["advisoryId"] = json!("CVE-2026-0002");
    unknown_kind["target"]["kind"] = json!("hypervisor");
    let mut bad_range = node_rule();
    bad_range["advisoryId"] = json!("CVE-2026-0003");
    bad_range["ranges"][0]["introduced"] = json!("not-a-version");
    let result = assess(
        node_artifact("22.12.0", "macos"),
        cached(signed_response(Some(section(vec![
            node_rule(),
            unknown_kind,
            bad_range,
        ])))),
    );
    assert_eq!(result["advisory_source"]["entries"], json!(1));
    assert_eq!(result["advisory_source"]["entries_skipped"], json!(2));
    assert_eq!(match_of(&result).0, json!("affected"));
}

#[test]
fn platform_and_bundled_component_rules_never_claim_a_match_they_cannot_see() {
    let mut linux_only = node_rule();
    linux_only["target"]["platforms"] = json!([{"os": "linux", "arch": "*"}]);
    let response = signed_response(Some(section(vec![linux_only])));
    let other = assess(node_artifact("22.12.0", "macos"), cached(response.clone()));
    assert_eq!(other["artifacts"][0]["matches"], json!([]));
    let unknown = assess(node_artifact("22.12.0", "unknown"), cached(response));
    assert_eq!(
        match_of(&unknown),
        (json!("unknown"), json!("platform_unknown"))
    );

    let mut bundled = node_rule();
    bundled["target"] = json!({
        "kind": "bundled_component",
        "component": "openssl",
        "host": {"family": "node", "vendor": "nodejs.org"},
        "platforms": [{"os": "*", "arch": "*"}],
        "versionScheme": "semver"
    });
    let result = assess(
        node_artifact("22.12.0", "macos"),
        cached(signed_response(Some(section(vec![bundled])))),
    );
    assert_eq!(
        match_of(&result),
        (json!("unknown"), json!("component_version_unobserved"))
    );
}

#[test]
fn no_cached_bundle_reports_an_absent_source() {
    let request = json!({"artifacts": [node_artifact("22.12.0", "macos")]});
    let reply = run_command(&serde_json::to_vec(&request).expect("request")).expect("reply");
    assert_eq!(reply["result"]["advisory_source"]["state"], json!("absent"));
}

fn anchored(response: Value) -> Value {
    let keyring = json!({"workspace_id": WORKSPACE, "keys": response["verificationKeys"]});
    json!({"response": response, "workspace_id": WORKSPACE, "sync_keyring": keyring, "now": now()})
}

fn trusted_node(version: &str, arch: &str) -> Value {
    let mut artifact = node_artifact(version, "macos");
    artifact["arch"] = json!(arch);
    artifact["executable_sha256"] = json!("a".repeat(64));
    artifact["identity_assurance"] = json!("locally_trusted");
    artifact
}

#[test]
fn repeated_ids_and_oversized_sections_are_skipped_not_fatal() {
    let mut bundled = node_rule();
    bundled["target"] = json!({
        "kind": "bundled_component",
        "component": "openssl",
        "host": {"family": "node", "vendor": "nodejs.org"},
        "platforms": [{"os": "*", "arch": "*"}],
        "versionScheme": "semver"
    });
    let repeated = assess(
        node_artifact("22.12.0", "macos"),
        cached(signed_response(Some(section(vec![node_rule(), bundled])))),
    );
    assert_eq!(repeated["advisory_source"]["entries"], json!(1));
    assert_eq!(repeated["advisory_source"]["entries_skipped"], json!(1));

    let mut entries: Vec<Value> = (0..1_100)
        .map(|index| {
            let mut rule = node_rule();
            rule["advisoryId"] = json!(format!("CVE-2026-{:05}", index + 20_000));
            rule["normalizedSeverity"] = json!("low");
            rule
        })
        .collect();
    let mut worst = node_rule();
    worst["normalizedSeverity"] = json!("critical");
    worst["knownExploited"] = json!(true);
    entries.push(worst);
    let large = assess(
        node_artifact("22.12.0", "macos"),
        cached(signed_response(Some(section(entries)))),
    );
    let source = &large["advisory_source"];
    assert_eq!(source["entries"], json!(1_024));
    assert_eq!(source["entries_truncated"], json!(77));
    assert_eq!(source["reason"], json!("section_truncated"));
    // The cut keeps the most severe entry, wherever it sat in the section.
    let kept = large["advisories"].as_array().expect("advisories");
    assert!(kept
        .iter()
        .any(|row| row["advisory_id"] == "CVE-2026-111497" && row["severity"] == "critical"));
}

#[test]
fn only_an_anchored_bundle_can_clear_a_runtime() {
    let response = signed_response(Some(section(vec![node_rule()])));
    let unanchored = assess(trusted_node("22.23.4", "arm64"), cached(response.clone()));
    assert_eq!(
        match_of(&unanchored),
        (json!("unknown"), json!("advisory_source_unanchored"))
    );
    assert_eq!(
        unanchored["advisory_source"]["coverage_reason"],
        json!("runtime_advisory_bundle_unanchored")
    );
    let still_affected = assess(trusted_node("22.12.0", "arm64"), cached(response.clone()));
    assert_eq!(match_of(&still_affected).0, json!("affected"));

    let anchored = assess(trusted_node("22.23.4", "arm64"), anchored(response));
    assert_eq!(
        match_of(&anchored),
        (json!("not_affected"), json!("outside_ranges"))
    );
    let source = &anchored["advisory_source"];
    assert_eq!(source["advisories_available"], json!(true));
    assert_eq!(source["coverage_reason"], Value::Null);
    assert!(source["valid_until"]
        .as_f64()
        .is_some_and(|until| until > now()));
}

#[test]
fn a_recorded_sync_must_name_this_workspace_and_a_version() {
    let response = signed_response(Some(section(vec![node_rule()])));
    let version = response["bundle"]["bundleVersion"].clone();
    let with = |entitlement: Value| {
        let mut input = cached(response.clone());
        input["entitlement"] = entitlement;
        assess(node_artifact("22.12.0", "macos"), input)["advisory_source"].clone()
    };
    let other = with(json!({"workspace_id": "other", "bundle_version": version}));
    assert_eq!(other["reason"], json!("sync_record_scope_mismatch"));
    let unversioned = with(json!({"workspace_id": WORKSPACE}));
    assert_eq!(unversioned["reason"], json!("sync_record_invalid"));
    assert_eq!(
        unversioned["coverage_reason"],
        json!("runtime_advisory_bundle_invalid")
    );
    let current = with(json!({"workspace_id": WORKSPACE, "bundle_version": version}));
    assert_eq!(current["state"], json!("verified"));
}

#[test]
fn a_universal_binary_confirms_no_single_architecture() {
    let mut arm_only = node_rule();
    arm_only["target"]["platforms"] = json!([{"os": "macos", "arch": "arm64"}]);
    let result = assess(
        trusted_node("22.12.0", "universal"),
        cached(signed_response(Some(section(vec![arm_only])))),
    );
    assert_eq!(
        match_of(&result),
        (json!("unknown"), json!("platform_unknown"))
    );
}

#[test]
fn a_grace_signing_key_bounds_how_long_the_bundle_counts_as_fresh() {
    let response = signed_response(Some(section(vec![node_rule()])));
    let grace = |keys: &mut Value| {
        keys[0]["state"] = json!("grace");
        keys[0]["validUntil"] = json!("2026-10-25T05:00:00.000Z");
    };
    let mut synced = anchored(response.clone());
    grace(&mut synced["sync_keyring"]["keys"]);
    let mut advertised = response;
    grace(&mut advertised["verificationKeys"]);
    for input in [synced, cached(advertised)] {
        let source = &assess(trusted_node("22.12.0", "arm64"), input)["advisory_source"];
        assert_eq!(source["state"], json!("verified"));
        assert_eq!(source["valid_until"], json!(1_792_904_400.0));
    }
}

#[test]
fn an_expired_bundle_keeps_its_launch_matches_only_while_its_grace_key_is_valid() {
    // The bundle expires at 2026-10-25T12:00Z (1_792_929_600).
    let expired = 1_792_929_600.0;
    let launch = |key_until: Option<&str>, at: f64| {
        let mut response = signed_response(Some(section(vec![node_rule()])));
        if let Some(until) = key_until {
            response["verificationKeys"][0]["state"] = json!("grace");
            response["verificationKeys"][0]["validUntil"] = json!(until);
        }
        let mut input = cached(response);
        input["now"] = json!(at);
        let input: super::CachedBundleInput = serde_json::from_value(input).expect("input");
        super::launch_bundle_advisories(Some(&input))
    };
    let held = launch(Some("2026-10-25T13:00:00.000Z"), expired + 1_800.0);
    assert_eq!(held.source["state"], json!("stale"));
    assert_eq!(held.source["valid_until"], json!(expired + 3_600.0));
    assert_eq!(held.advisories.len(), 1);
    let lapsed = launch(Some("2026-10-25T13:00:00.000Z"), expired + 7_200.0);
    assert!(lapsed.advisories.is_empty(), "{}", lapsed.source);
    let active = launch(None, expired + 400_000.0);
    assert_eq!(active.source["state"], json!("stale"));
    assert_eq!(active.source["valid_until"], Value::Null);
    assert_eq!(active.advisories.len(), 1);
}
