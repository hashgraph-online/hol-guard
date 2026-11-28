use guard_contracts::{
    ProviderCapabilityV1, ProviderInventoryV1, ProviderSignalStateV1, ProviderSignalV1,
    ProviderSubjectKindV1, ProviderSubjectV1, ProviderVerdictV1,
};
use serde_json::json;

use super::provider_finding_row;
use crate::provider_integration_compile::{
    compile_provider_integration, CompiledProviderIntegrationV1,
};

const ID: &str = "provider.exampleshield";

fn provider() -> CompiledProviderIntegrationV1 {
    let manifest = json!({
        "schemaVersion": "guard.provider-integration.v1",
        "id": ID,
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
            "request": {"method": "POST", "path": "/v1/guard/origin", "body": {"origin": {"fact": "target.origin"}}},
            "response": {
                "verdict": {"pointer": "/verdict", "map": {"clean": "ok", "malicious": "danger"}},
                "reasonCodes": {
                    "pointer": "/reasons",
                    "allow": ["phishing", "malware", "new_domain", "typosquat", "lookalike"],
                    "labels": {
                        "phishing": "Reported for phishing",
                        "malware": "Serves malware",
                        "new_domain": "Registered recently",
                        "lookalike": "Looks like another site"
                    }
                }
            },
            "shares": ["target.origin"]
        }],
        "limits": {"timeoutMs": 1200, "maxResponseBytes": 16384, "maxRequestsPerMinute": 30},
        "privacyUrl": "https://exampleshield.example/privacy",
        "termsUrl": "https://exampleshield.example/terms"
    });
    compile_provider_integration(&serde_json::to_vec(&manifest).unwrap(), &[])
        .expect("fixture manifest compiles")
}

fn signal(verdict: ProviderVerdictV1, codes: &[&str]) -> ProviderSignalV1 {
    ProviderSignalV1 {
        version: 1,
        provider_id: ID.into(),
        capability: ProviderCapabilityV1::OriginReputation,
        subject: ProviderSubjectV1 {
            kind: ProviderSubjectKindV1::Origin,
            digest: "a".repeat(64),
        },
        verdict,
        reason_codes: codes.iter().map(|code| (*code).to_owned()).collect(),
        observed_at_ms: 1_000,
        expires_at_ms: 61_000,
        inventory: ProviderInventoryV1::ProviderSide,
        state: ProviderSignalStateV1::Fresh,
    }
}

#[test]
fn a_row_carries_manifest_text_only() {
    let row = provider_finding_row(
        &provider(),
        &signal(
            ProviderVerdictV1::Danger,
            &["phishing", "typosquat", "phishing"],
        ),
    )
    .expect("row");
    assert_eq!(row.provider_name, "ExampleShield");
    assert_eq!(row.capability, ProviderCapabilityV1::OriginReputation);
    assert_eq!(row.verdict, ProviderVerdictV1::Danger);
    assert_eq!(row.observed_at_ms, 1_000);
    // `typosquat` is allowed but has no label, so it is left off; a repeated code shows once.
    assert_eq!(row.reason_labels, ["Reported for phishing"]);
    assert!(!row.sponsored);
}

#[test]
fn a_row_shows_at_most_three_reason_labels() {
    let row = provider_finding_row(
        &provider(),
        &signal(
            ProviderVerdictV1::Danger,
            &["lookalike", "malware", "phishing", "new_domain"],
        ),
    )
    .expect("row");
    assert_eq!(
        row.reason_labels,
        [
            "Looks like another site",
            "Serves malware",
            "Reported for phishing"
        ]
    );
}

#[test]
fn an_undeclared_code_or_foreign_signal_never_reaches_the_card() {
    let row = provider_finding_row(
        &provider(),
        &signal(ProviderVerdictV1::Caution, &["unlisted"]),
    )
    .expect("row");
    assert!(row.reason_labels.is_empty());

    let mut other = signal(ProviderVerdictV1::Danger, &["phishing"]);
    other.provider_id = "provider.otherprovider".into();
    assert_eq!(provider_finding_row(&provider(), &other), None);

    let mut undeclared = signal(ProviderVerdictV1::Danger, &["phishing"]);
    undeclared.capability = ProviderCapabilityV1::ScriptIntegrity;
    assert_eq!(provider_finding_row(&provider(), &undeclared), None);

    let mut malformed = signal(ProviderVerdictV1::Danger, &["phishing"]);
    malformed.subject.digest = "not-a-digest".into();
    assert_eq!(provider_finding_row(&provider(), &malformed), None);
}
