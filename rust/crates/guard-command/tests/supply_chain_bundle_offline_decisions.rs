//! Offline decisions over a cached supply-chain bundle.
//!
//! A workspace that cannot reach Guard Cloud still answers from the bundle it
//! last cached, so these cover what that answer must be: a high-confidence
//! package blocks, a stale low-risk one drops to monitor, an emergency deny
//! blocks even with no package record and even once the bundle is stale, and a
//! scoped record never answers for the unscoped name that merely shares its
//! leaf.

use guard_command::supply_chain_bundle::{
    evaluate_cached_supply_chain_bundle, load_supply_chain_bundle_response,
    OfflineSupplyChainDecision, SupplyChainBundleResponse,
};
use serde_json::{json, Value};

/// 2026-05-19T00:00:00Z, the moment every bundle below is generated at.
const GENERATED_AT_EPOCH_SECONDS: f64 = 1_779_148_800.0;

fn advisory() -> Value {
    json!({
        "advisoryId": "GHSA-vh95-rmgr-6w4m",
        "aliases": ["CVE-2020-7598"],
        "confidence": 990,
        "exploitLevel": "active",
        "knownExploited": true,
        "malwareState": "none",
        "normalizedSeverity": "critical",
        "recommendedFixVersion": "1.2.9",
        "sourceKey": "ghsa",
        "summary": "Prototype pollution in minimist",
        "title": "Prototype pollution in minimist",
    })
}

fn package_record(
    ecosystem: &str,
    name: &str,
    namespace: Option<&str>,
    version: &str,
    action: &str,
) -> Value {
    let qualified = match namespace {
        Some(scope) => format!("{scope}/{name}"),
        None => name.to_owned(),
    };
    json!({
        "confidence": 990,
        "defaultAction": action,
        "ecosystem": ecosystem,
        "exploitLevel": "active",
        "knownExploited": true,
        "malwareState": "known",
        "name": name,
        "namespace": namespace,
        "normalizedSeverity": "critical",
        "packageAgeState": "watch",
        "purl": format!("pkg:{ecosystem}/{qualified}@{version}"),
        "reachability": "reachable",
        "recommendedFixVersion": "1.2.9",
        "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
        "riskScore": 980,
        "sourceIntegrityState": "high-risk",
        "version": version,
    })
}

/// A low-risk package record: nothing about it is high-confidence, so a stale
/// bundle must stop blocking on it.
fn low_risk_package_record() -> Value {
    json!({
        "confidence": 990,
        "defaultAction": "monitor",
        "ecosystem": "npm",
        "exploitLevel": "none",
        "knownExploited": false,
        "malwareState": "none",
        "name": "minimist",
        "namespace": null,
        "normalizedSeverity": "low",
        "packageAgeState": "watch",
        "purl": "pkg:npm/minimist@1.2.8",
        "reachability": "reachable",
        "recommendedFixVersion": "1.2.9",
        "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
        "riskScore": 220,
        "sourceIntegrityState": "high-risk",
        "version": "1.2.8",
    })
}

fn bundle(packages: Value, emergency_denylist: Value, expires_at: &str) -> Value {
    json!({
        "advisories": [advisory()],
        "bundleVersion": "1747612800000-deadbeef",
        "emergencyDenylist": emergency_denylist,
        "expiresAt": expires_at,
        "feedSnapshotHash": "feed-snapshot-1",
        "generatedAt": "2026-05-19T00:00:00Z",
        "keyId": "guard-bundle-key-2026-05",
        "packages": packages,
        "policyHash": "policy-hash-1",
        "policyRules": [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [{
            "payloadHash": "ghsa-feed-hash",
            "sourceKey": "ghsa",
            "staleStatus": "fresh",
        }],
        "tier": "premium",
        "workspaceId": "workspace-alpha",
    })
}

/// The response envelope around `bundle`. Offline evaluation reads a response
/// that was verified when it was cached, so the signature here is a placeholder
/// the loader accepts and no decision below consults.
fn cached(bundle: Value) -> SupplyChainBundleResponse {
    let raw = json!({
        "bundle": bundle,
        "payloadHash": "0".repeat(64),
        "signature": "cGxhY2Vob2xkZXItc2lnbmF0dXJl",
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [{
            "fingerprintSha256": "0".repeat(64),
            "keyId": "guard-bundle-key-2026-05",
            "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nplaceholder\n-----END PUBLIC KEY-----",
            "state": "active",
            "validUntil": null,
        }],
    });
    load_supply_chain_bundle_response(&raw).expect("response loads")
}

fn decide(
    response: &SupplyChainBundleResponse,
    package_name: &str,
    package_version: &str,
    ecosystem: Option<&str>,
    now: f64,
) -> OfflineSupplyChainDecision {
    evaluate_cached_supply_chain_bundle(
        response,
        package_name,
        Some(package_version),
        ecosystem,
        Some(now),
    )
}

#[test]
fn blocks_a_high_confidence_package_and_monitors_a_stale_low_risk_one() {
    let blocking = cached(bundle(
        json!([package_record("npm", "minimist", None, "1.2.8", "block")]),
        json!([]),
        "2026-05-19T12:00:00Z",
    ));
    let decision = decide(
        &blocking,
        "minimist",
        "1.2.8",
        None,
        GENERATED_AT_EPOCH_SECONDS + 60.0,
    );
    assert_eq!(decision.action, "block");
    assert!(!decision.stale);
    assert_eq!(decision.reason, "known_malware_or_kev");

    let low_risk = cached(bundle(
        json!([low_risk_package_record()]),
        json!([]),
        "2026-05-18T01:00:00Z",
    ));
    let decision = decide(
        &low_risk,
        "minimist",
        "1.2.8",
        None,
        GENERATED_AT_EPOCH_SECONDS,
    );
    assert_eq!(decision.action, "monitor");
    assert!(decision.stale);
    assert_eq!(decision.reason, "stale_low_confidence");
}

#[test]
fn an_emergency_deny_blocks_a_package_the_bundle_does_not_list() {
    let response = cached(bundle(
        json!([]),
        json!([{
            "ecosystem": "npm",
            "name": "minimist",
            "namespace": null,
            "reason": "known_malware",
            "recommendedFixVersion": "1.2.9",
        }]),
        "2026-05-19T12:00:00Z",
    ));

    // The caller's ecosystem is uppercase, which must normalize to the entry's.
    let decision = decide(
        &response,
        "minimist",
        "1.2.8",
        Some("NPM"),
        GENERATED_AT_EPOCH_SECONDS + 60.0,
    );

    assert_eq!(decision.action, "block");
    assert_eq!(decision.reason, "known_malware");
    assert!(!decision.stale);
    assert_eq!(
        decision.recommended_fix_version,
        Some("1.2.9".to_owned()),
        "the caller is told what to move to"
    );
    assert!(decision.emergency_deny);
}

#[test]
fn an_emergency_deny_still_blocks_once_the_bundle_is_stale() {
    let response = cached(bundle(
        json!([]),
        json!([{
            "ecosystem": "npm",
            "name": "minimist",
            "namespace": null,
            "reason": "critical_active_exploit",
            "recommendedFixVersion": null,
        }]),
        "2026-05-18T01:00:00Z",
    ));

    let decision = decide(
        &response,
        "minimist",
        "9.9.9",
        Some("npm"),
        GENERATED_AT_EPOCH_SECONDS,
    );

    assert_eq!(decision.action, "block");
    assert_eq!(decision.reason, "critical_active_exploit");
    assert!(decision.stale);
}

#[test]
fn a_scoped_record_does_not_answer_for_the_unscoped_name() {
    let response = cached(bundle(
        json!([package_record(
            "npm",
            "minimist",
            Some("@scope"),
            "1.2.8",
            "block"
        )]),
        json!([]),
        "2026-05-19T12:00:00Z",
    ));

    let decision = decide(
        &response,
        "minimist",
        "1.2.8",
        None,
        GENERATED_AT_EPOCH_SECONDS + 60.0,
    );

    assert_eq!(decision.action, "monitor");
    assert!(decision.matched_advisory_ids.is_empty());
    assert_eq!(decision.reason, "no_cached_match");
}

#[test]
fn each_scope_and_the_unscoped_leaf_keep_their_own_record() {
    let response = cached(bundle(
        json!([
            package_record("npm", "pkg", None, "1.2.3", "monitor"),
            package_record("npm", "pkg", Some("@one"), "1.2.3", "block"),
            package_record("npm", "pkg", Some("@two"), "1.2.3", "warn"),
        ]),
        json!([]),
        "2026-05-19T12:00:00Z",
    ));
    let now = GENERATED_AT_EPOCH_SECONDS + 1.0;

    assert_eq!(
        decide(&response, "pkg", "1.2.3", Some("npm"), now).action,
        "monitor"
    );
    assert_eq!(
        decide(&response, "@one/pkg", "1.2.3", Some("npm"), now).action,
        "block"
    );
    assert_eq!(
        decide(&response, "@two/pkg", "1.2.3", Some("npm"), now).action,
        "warn"
    );
}

#[test]
fn each_ecosystem_matches_a_name_the_way_that_ecosystem_does() {
    // npm lowercases, PyPI also folds `_` to `-`, and Go is case-sensitive.
    let response = cached(bundle(
        json!([
            package_record("npm", "Pkg", Some("@Scope"), "1.2.3", "block"),
            package_record("pypi", "Foo_Bar", None, "1.2.3", "block"),
            package_record("go", "Example.com/Org/Repo", None, "1.2.3", "block"),
        ]),
        json!([]),
        "2026-05-19T12:00:00Z",
    ));
    let now = GENERATED_AT_EPOCH_SECONDS + 60.0;

    assert_eq!(
        decide(&response, "@scope/pkg", "1.2.3", Some("npm"), now).action,
        "block"
    );
    assert_eq!(
        decide(&response, "foo-bar", "1.2.3", Some("pypi"), now).action,
        "block"
    );
    assert_eq!(
        decide(&response, "@scope/pkg", "1.2.3", Some("NPM"), now).action,
        "block",
        "the caller's ecosystem is normalized before it is compared"
    );
    assert_eq!(
        decide(&response, "Example.com/Org/Repo", "1.2.3", Some("go"), now).action,
        "block"
    );
    assert_eq!(
        decide(&response, "example.com/org/repo", "1.2.3", Some("go"), now).reason,
        "no_cached_match",
        "a Go module path that differs only in case is a different module"
    );
}
