//! Parity vectors recorded from the Python `supply_chain_findings`,
//! `listed_packages`, `unresolved_packages`, `unchecked_packages` and
//! `keep_package_identities` helpers before they were deleted, plus named
//! identity and coverage-gap cases.

use super::*;
use std::io::Read;

const VECTORS: &[u8] = include_bytes!("../testdata/workspace_package_findings_vectors.json.gz");

fn vectors() -> Value {
    let mut text = String::new();
    flate2::read::GzDecoder::new(VECTORS)
        .read_to_string(&mut text)
        .unwrap();
    serde_json::from_str(&text).unwrap()
}

fn identities(findings: Value, earlier: Value, listed: Option<Vec<[&str; 3]>>) -> Value {
    package_identities(&PackageAuditPackageIdentitiesQueryV1 {
        findings: serde_json::from_value(findings).unwrap(),
        earlier: serde_json::from_value(earlier).unwrap(),
        listed: listed.map(|listed| {
            listed
                .into_iter()
                .map(|coordinate| coordinate.map(str::to_owned))
                .collect()
        }),
    })
}

#[test]
fn workspace_findings_match_the_python_projection() {
    let vectors = vectors();
    let cases = vectors["workspace_findings"].as_array().unwrap();
    assert!(cases.len() >= 500);
    let mut findings = 0;
    for (index, case) in cases.iter().enumerate() {
        let query = PackageAuditWorkspaceFindingsQueryV1 {
            worktree_key: case["worktree_key"].as_str().unwrap().to_owned(),
            payload: case["payload"].clone(),
        };
        assert_eq!(
            workspace_findings(&query),
            case["expected"],
            "vector {index}"
        );
        findings += case["expected"]["findings"].as_array().unwrap().len();
    }
    assert!(findings >= 500);
}

#[test]
fn package_identities_match_the_python_carry() {
    let vectors = vectors();
    let cases = vectors["package_identities"].as_array().unwrap();
    assert!(cases.len() >= 500);
    for (index, case) in cases.iter().enumerate() {
        let query = PackageAuditPackageIdentitiesQueryV1 {
            findings: serde_json::from_value(case["findings"].clone()).unwrap(),
            earlier: serde_json::from_value(case["earlier"].clone()).unwrap(),
            listed: serde_json::from_value(case["listed"].clone()).unwrap(),
        };
        assert_eq!(
            package_identities(&query),
            case["expected"],
            "vector {index}"
        );
    }
}

fn package(id: &str, name: &str) -> Value {
    json!({
        "finding_id": id,
        "source_kind": "supply_chain",
        "ecosystem": "npm",
        "package_name": name,
        "package_version": "7.0.0",
    })
}

#[test]
fn a_scoped_package_keeps_the_id_an_earlier_run_gave_its_bare_name() {
    let reply = identities(
        json!([package("new", "@babel/traverse")]),
        json!([package("old", "traverse")]),
        Some(vec![["npm", "@babel/traverse", "7.0.0"]]),
    );

    assert_eq!(reply["finding_ids"], json!(["old"]));
    assert_eq!(reply["settled"], json!([false]));
}

#[test]
fn a_bare_name_two_packages_could_take_stays_with_neither() {
    let reply = identities(
        json!([
            package("babel", "@babel/traverse"),
            package("other", "@other/traverse")
        ]),
        json!([package("old", "traverse")]),
        None,
    );

    assert_eq!(reply["finding_ids"], json!(["babel", "other"]));
}

#[test]
fn an_earlier_package_the_audit_no_longer_lists_is_settled() {
    let reply = identities(
        json!([{"finding_id": "secret", "source_kind": "secret"}]),
        json!([
            package("gone", "minimist"),
            package("kept", "left-pad"),
            "not a finding"
        ]),
        Some(vec![["npm", "left-pad", "7.0.0"]]),
    );

    assert_eq!(reply["finding_ids"], json!(["secret"]));
    assert_eq!(reply["settled"], json!([true, false, false]));
}

#[test]
fn a_lookup_the_offline_run_could_not_answer_is_a_coverage_gap() {
    let payload = json!({"evaluation": {"bundle_version": null, "packages": [
        {"decision": "ask", "ecosystem": "npm", "name": "a", "reasons": [{"code": "cloud_timeout"}]},
        {"decision": "warn", "ecosystem": "npm", "name": "b", "reasons": [{"code": "no_cached_match"}]},
    ]}});

    let reply = workspace_findings(&PackageAuditWorkspaceFindingsQueryV1 {
        worktree_key: "w".repeat(64),
        payload,
    });

    let names: Vec<&str> = reply["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["package_name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["b"]);
    assert_eq!(reply["unresolved"], json!(1));
    assert_eq!(reply["unchecked"], json!(1));
    assert_eq!(reply["listed"], json!([["npm", "a", ""], ["npm", "b", ""]]));
}
