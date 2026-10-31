//! Reading a supply-chain bundle response onto its types.
//!
//! The verifier parses the bundle before it checks anything else, so these
//! cover what parsing alone must do: merge identical package records, read a
//! legacy Packagist name into its vendor and package, refuse two different
//! records for one canonical package, refuse identity fields that do not fit
//! their ecosystem, and read the optional sections a portal-signed bundle may
//! carry.

use guard_command::supply_chain_bundle::{
    load_supply_chain_bundle_response, SupplyChainBundleError, SupplyChainBundleResponse,
};
use serde_json::{json, Value};

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

fn npm_record(name: &str, namespace: Option<&str>, action: &str) -> Value {
    package_record("npm", name, namespace, "1.2.3", action)
}

fn bundle(packages: Value) -> Value {
    json!({
        "advisories": [{
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
        }],
        "bundleVersion": "1747612800000-deadbeef",
        "expiresAt": "2026-05-19T12:00:00Z",
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

/// The response envelope around `bundle`. Loading checks no signature, so the
/// signature and keyring here are placeholders the loader accepts.
fn load(bundle: Value) -> Result<SupplyChainBundleResponse, SupplyChainBundleError> {
    load_supply_chain_bundle_response(&json!({
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
    }))
}

fn malformed_message(bundle: Value) -> String {
    match load(bundle) {
        Err(SupplyChainBundleError::Malformed(message)) => message,
        Err(other) => panic!("expected a malformed bundle, got {other:?}"),
        Ok(_) => panic!("expected a malformed bundle, but it loaded"),
    }
}

#[test]
fn identical_canonical_package_records_merge_into_one() {
    let record = npm_record("pkg", Some("@scope"), "block");

    let response = load(bundle(json!([record.clone(), record]))).expect("bundle loads");

    assert_eq!(response.bundle.packages.len(), 1);
    assert_eq!(
        response.bundle.packages[0].namespace.as_deref(),
        Some("@scope")
    );
}

#[test]
fn a_legacy_qualified_packagist_name_reads_as_vendor_and_package() {
    let record = package_record("packagist", "Laravel/Framework", None, "11.1.0", "block");

    let response = load(bundle(json!([record]))).expect("bundle loads");

    let package = &response.bundle.packages[0];
    assert_eq!(package.ecosystem, "packagist");
    assert_eq!(package.namespace.as_deref(), Some("laravel"));
    assert_eq!(package.name, "framework");
}

#[test]
fn two_different_records_for_one_canonical_package_are_refused() {
    let pairs = [
        (
            npm_record("pkg", Some("@scope"), "block"),
            npm_record("pkg", Some("@scope"), "warn"),
        ),
        (
            npm_record("Pkg", Some("@Scope"), "block"),
            npm_record("pkg", Some("@scope"), "warn"),
        ),
    ];
    for (first, second) in pairs {
        let message = malformed_message(bundle(json!([first, second])));

        assert!(
            message.starts_with("Conflicting package records")
                && message.contains("npm:@scope/pkg@1.2.3"),
            "unexpected message: {message}"
        );
    }
}

#[test]
fn identity_fields_that_do_not_fit_their_ecosystem_are_refused() {
    let records = [
        npm_record("pkg", Some("scope"), "block"),
        npm_record("pkg", Some("@scope@"), "block"),
        npm_record("@scope/pkg", None, "block"),
        package_record("pypi", "org/pkg", None, "1.2.3", "block"),
        package_record("packagist", "pkg", None, "1.2.3", "block"),
    ];
    for record in records {
        let message = malformed_message(bundle(json!([record])));

        assert!(
            message.contains("Invalid package identity"),
            "unexpected message: {message}"
        );
    }
}

#[test]
fn a_portal_signed_bundle_with_an_emergency_denylist_loads() {
    let mut raw = bundle(json!([npm_record("minimist", None, "block")]));
    raw["emergencyDenylist"] = json!([{
        "ecosystem": "npm",
        "name": "minimist",
        "namespace": null,
        "reason": "known_malware",
        "recommendedFixVersion": "1.2.9",
    }]);

    let response = load(raw).expect("bundle loads");

    assert_eq!(response.bundle.emergency_denylist.len(), 1);
    assert_eq!(
        response.bundle.emergency_denylist[0].reason,
        "known_malware"
    );
}

#[test]
fn a_portal_signed_bundle_with_sparse_policy_rules_loads() {
    let mut raw = bundle(json!([npm_record("minimist", None, "block")]));
    raw["policyRules"] = json!([{ "action": "block", "ruleId": "rule-1" }]);

    let response = load(raw).expect("bundle loads");

    assert_eq!(response.bundle.policy_rules.len(), 1);
    assert_eq!(response.bundle.policy_rules[0].rule_id, "rule-1");
}
