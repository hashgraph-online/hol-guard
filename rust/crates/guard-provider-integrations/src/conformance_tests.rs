use guard_contracts::{
    ProviderCapabilityV1 as Cap, ProviderShareableFactV1 as Fact, ProviderVerdictV1 as V,
};
use serde_json::{json, Value};

use super::noise_checks::check_bounded_prompt;
use super::*;

fn manifest() -> Value {
    json!({
        "schemaVersion": "guard.provider-integration.v1",
        "id": "provider.exampleshield",
        "name": "ExampleShield",
        "publisher": {"name": "ExampleShield Inc.", "url": "https://exampleshield.example", "verified": false},
        "summary": "Checks the sites an agent opens against your ExampleShield account.",
        "surfaces": ["browser"],
        "auth": {
            "kind": "api-key",
            "header": "x-provider-key",
            "keyFormat": {"minLength": 24, "maxLength": 128, "charset": "base64url"},
            "obtainUrl": "https://exampleshield.example/keys"
        },
        "hosts": ["api.exampleshield.example"],
        "capabilities": [{
            "id": "browser.origin-reputation",
            "request": {
                "method": "POST",
                "path": "/v1/guard/origin",
                "body": {"origin": {"fact": "target.origin"}}
            },
            "response": {
                "verdict": {"pointer": "/verdict", "map": {"clean": "ok", "suspicious": "caution", "malicious": "danger"}},
                "reasonCodes": {
                    "pointer": "/reasons",
                    "allow": ["phishing", "malware", "new_domain", "typosquat"],
                    "labels": {"phishing": "Reported for phishing", "new_domain": "Registered recently"}
                },
                "ttlSeconds": {"pointer": "/ttl", "min": 60, "max": 86400}
            },
            "shares": ["target.origin"]
        }],
        "verify": {"method": "GET", "path": "/v1/guard/key"},
        "limits": {"timeoutMs": 1200, "maxResponseBytes": 64, "maxRequestsPerMinute": 30},
        "privacyUrl": "https://exampleshield.example/privacy",
        "termsUrl": "https://exampleshield.example/terms"
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

const OVERSIZE: &[u8] = br#"{"verdict":"clean","reasons":[],"ttl":60,"padding":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#;

fn signal(
    name: &'static str,
    body: &'static [u8],
    verdict: V,
    reasons: &[&str],
) -> Recording<'static> {
    Recording {
        name,
        capability: Cap::OriginReputation,
        status: 200,
        body,
        expect: RecordedExpectation::Signal {
            verdict,
            reason_codes: reasons.iter().map(|code| (*code).to_owned()).collect(),
        },
    }
}

fn failure(
    name: &'static str,
    status: u16,
    body: &'static [u8],
    failure: RecordedFailure,
) -> Recording<'static> {
    Recording {
        name,
        capability: Cap::OriginReputation,
        status,
        body,
        expect: RecordedExpectation::Failure(failure),
    }
}

fn recordings() -> Vec<Recording<'static>> {
    vec![
        signal("clean", br#"{"verdict":"clean","ttl":600}"#, V::Ok, &[]),
        signal(
            "suspicious",
            br#"{"verdict":"suspicious","reasons":["new_domain","sponsored"]}"#,
            V::Caution,
            &["new_domain"],
        ),
        signal(
            "malicious",
            br#"{"verdict":"malicious","reasons":["phishing"]}"#,
            V::Danger,
            &["phishing"],
        ),
        signal("unmapped", br#"{"verdict":"pending"}"#, V::Unknown, &[]),
        failure("unauthorized", 401, b"{}", RecordedFailure::Unauthorized),
        failure("rate-limited", 429, b"{}", RecordedFailure::RateLimited),
        failure("oversize", 200, OVERSIZE, RecordedFailure::Oversize),
        failure(
            "malformed",
            200,
            br#"{"verdict":"clean","#,
            RecordedFailure::Malformed,
        ),
    ]
}

fn corpus() -> Vec<BaselineDecision> {
    let mut rows = vec![BaselineDecision::Allow; 40];
    rows.extend([BaselineDecision::Review, BaselineDecision::Block]);
    rows
}

fn problems(report: &ConformanceReport, id: &str) -> Vec<String> {
    report
        .checks
        .iter()
        .find(|check| check.id == id)
        .map(|check| check.problems.clone())
        .unwrap_or_else(|| panic!("{id}"))
}

#[test]
fn the_reference_manifest_passes_all_five_checks() {
    let report = run_conformance(&bytes(&manifest()), &recordings(), &corpus());
    assert_eq!(
        report.provider_id.as_deref(),
        Some("provider.exampleshield")
    );
    assert_eq!(
        report
            .checks
            .iter()
            .map(|check| check.id)
            .collect::<Vec<_>>(),
        CONFORMANCE_CHECKS
    );
    assert!(report.passed(), "{report:#?}");
}

#[test]
fn a_manifest_that_does_not_compile_fails_every_check() {
    let mut value = manifest();
    value["publisher"]["verified"] = json!(true);
    let report = run_conformance(&bytes(&value), &recordings(), &corpus());
    assert_eq!(report.provider_id, None);
    assert_eq!(report.checks.len(), 5);
    assert!(
        report.checks.iter().all(|check| !check.passed()),
        "{report:#?}"
    );
    assert!(problems(&report, "compile")[0].starts_with("manifest did not compile: "));
}

#[test]
fn every_verdict_and_failure_needs_a_recording() {
    let kept: Vec<Recording<'static>> = recordings()
        .into_iter()
        .filter(|recording| !matches!(recording.name, "unmapped" | "rate-limited"))
        .collect();
    let report = run_conformance(&bytes(&manifest()), &kept, &corpus());
    assert_eq!(
        problems(&report, "recordings"),
        [
            "browser.origin-reputation: no recording answers unknown",
            "browser.origin-reputation: no recording fails as rate_limited",
        ]
    );
}

#[test]
fn a_recording_that_reads_differently_fails() {
    let mut set = recordings();
    set[0].expect = RecordedExpectation::Signal {
        verdict: V::Caution,
        reason_codes: Vec::new(),
    };
    set[4].status = 503;
    let report = run_conformance(&bytes(&manifest()), &set, &corpus());
    let found = problems(&report, "recordings");
    assert!(
        found.contains(&"clean: recorded as caution, reads as ok with 0 reason code(s)".to_owned()),
        "{found:?}"
    );
    assert!(
        found.contains(&"unauthorized: recorded as unauthorized, reads as status".to_owned()),
        "{found:?}"
    );
    assert!(!found.contains(&"browser.origin-reputation: no recording answers caution".to_owned()));
}

#[test]
fn a_recording_for_an_undeclared_capability_fails() {
    let mut set = recordings();
    set.push(Recording {
        capability: Cap::DownloadReputation,
        ..signal("download", br#"{"verdict":"clean"}"#, V::Ok, &[])
    });
    let report = run_conformance(&bytes(&manifest()), &set, &corpus());
    assert_eq!(
        problems(&report, "recordings"),
        ["download: the manifest has no browser.download-reputation capability"]
    );
}

#[test]
fn the_failure_order_matches_the_resident() {
    let compiled = compile_provider_integration(&bytes(&manifest()), &[]).unwrap();
    let capability = &compiled.capabilities[0];
    assert_eq!(
        recorded_outcome(capability, 64, 403, b"{}"),
        Err(RecordedFailure::Unauthorized)
    );
    assert_eq!(
        recorded_outcome(capability, 64, 302, b"{}"),
        Err(RecordedFailure::Status)
    );
    assert_eq!(
        recorded_outcome(capability, 64, 500, OVERSIZE),
        Err(RecordedFailure::Oversize)
    );
    assert_eq!(
        recorded_outcome(capability, 64, 500, b"{}"),
        Err(RecordedFailure::Status)
    );
    assert_eq!(
        recorded_outcome(capability, 64, 200, OVERSIZE),
        Err(RecordedFailure::Oversize)
    );
    assert_eq!(
        recorded_outcome(capability, 64, 200, b"[]").map(|answer| answer.verdict),
        Ok(V::Unknown)
    );
}

#[test]
fn a_body_that_disagrees_with_its_share_list_fails() {
    let mut compiled = compile_provider_integration(&bytes(&manifest()), &[]).unwrap();
    assert!(check_share_set(&compiled).passed());

    compiled.capabilities[0].shares.insert(Fact::GuardVersion);
    assert_eq!(
        check_share_set(&compiled).problems,
        ["browser.origin-reputation: shares and the body disagree on guard.version"]
    );

    let mut compiled = compile_provider_integration(&bytes(&manifest()), &[]).unwrap();
    compiled.capabilities[0]
        .request
        .body
        .push(("build".to_owned(), Fact::GuardVersion));
    assert_eq!(
        check_share_set(&compiled).problems,
        ["browser.origin-reputation: shares and the body disagree on guard.version"]
    );
}

#[test]
fn every_fact_has_a_distinct_canary() {
    let facts = canary_facts();
    assert_eq!(facts.len(), Fact::ALL.len());
    assert_eq!(
        facts["page.script_hashes"],
        json!(["conformance-canary-page.script_hashes"])
    );
    for fact in Fact::ALL {
        let others = Fact::ALL.iter().filter(|other| **other != fact);
        for other in others {
            assert!(
                !canary(fact).contains(&canary(*other)),
                "{fact:?} {other:?}"
            );
        }
    }
}

#[test]
fn an_empty_corpus_fails_the_no_added_prompt_check() {
    let report = run_conformance(&bytes(&manifest()), &recordings(), &[]);
    assert_eq!(
        problems(&report, "no-added-prompt"),
        ["the benign browser corpus is empty"]
    );
    assert!(problems(&report, "bounded-prompt").is_empty());
}

#[test]
fn caution_on_every_subject_stays_inside_the_caps() {
    let compiled = compile_provider_integration(&bytes(&manifest()), &[]).unwrap();
    for rows in [1, 3, 4, 200] {
        assert!(check_bounded_prompt(&compiled, rows).passed(), "{rows}");
    }
}
