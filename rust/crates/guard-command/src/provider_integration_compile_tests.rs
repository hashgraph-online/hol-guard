use serde_json::{json, Value};

use super::*;

const ID: &str = "provider.exampleshield";

pub(super) fn manifest() -> Value {
    json!({
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
        "limits": {"timeoutMs": 1200, "maxResponseBytes": 16384, "maxRequestsPerMinute": 30},
        "privacyUrl": "https://exampleshield.example/privacy",
        "termsUrl": "https://exampleshield.example/terms"
    })
}

pub(super) fn compile(value: &Value) -> CompileResult<CompiledProviderIntegrationV1> {
    compile_provider_integration(&serde_json::to_vec(value).unwrap(), &[])
}

pub(super) fn with(pointer: &str, replacement: Value) -> Value {
    let mut value = manifest();
    *value
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("{pointer}")) = replacement;
    value
}

pub(super) fn without(parent: &str, key: &str) -> Value {
    let mut value = manifest();
    value
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .unwrap()
        .remove(key);
    value
}

pub(super) fn refused(value: Value, expected: ProviderIntegrationCompileError) {
    assert_eq!(compile(&value), Err(expected), "{value}");
}

#[test]
fn the_reference_manifest_compiles() {
    let compiled = compile(&manifest()).unwrap();
    assert_eq!(compiled.id, ID);
    assert!(!compiled.verified);
    assert_eq!(compiled.auth.header, "x-provider-key");
    assert_eq!(compiled.auth.key_charset, ProviderKeyCharsetV1::Base64url);
    assert_eq!(compiled.hosts, ["api.exampleshield.example"]);
    let capability = &compiled.capabilities[0];
    assert_eq!(
        capability.capability,
        ProviderCapabilityV1::OriginReputation
    );
    assert_eq!(
        capability.request.url(),
        "https://api.exampleshield.example/v1/guard/origin"
    );
    assert_eq!(
        capability.request.body,
        [("origin".to_owned(), ProviderShareableFactV1::TargetOrigin)]
    );
    assert_eq!(
        capability.shares,
        BTreeSet::from([ProviderShareableFactV1::TargetOrigin])
    );
    assert_eq!(
        capability.verdict_map.get("malicious"),
        Some(&ProviderVerdictV1::Danger)
    );
    let codes = capability.reason_codes.as_ref().unwrap();
    assert_eq!(codes.allow.len(), 4);
    assert_eq!(codes.labels.len(), 2);
    assert_eq!(capability.ttl.as_ref().unwrap().max_seconds, 86_400);
    assert_eq!(
        compiled.verify.unwrap().url(),
        "https://api.exampleshield.example/v1/guard/key"
    );
    assert_eq!(compiled.limits.timeout_ms, 1200);
}

#[test]
fn the_compiled_manifest_carries_the_digest_of_its_source_bytes() {
    let bytes = serde_json::to_vec(&manifest()).unwrap();
    let compiled = compile_provider_integration(&bytes, &[]).unwrap();
    assert_eq!(
        compiled.manifest_digest,
        hex::encode(Sha256::digest(&bytes))
    );
    let mut changed = manifest();
    changed["summary"] = json!("Checks the sites an agent opens.");
    let other = compile_provider_integration(&serde_json::to_vec(&changed).unwrap(), &[]).unwrap();
    assert_ne!(other.manifest_digest, compiled.manifest_digest);
}

#[test]
fn bytes_json_and_version_are_checked_first() {
    assert_eq!(
        compile_provider_integration(b"", &[]),
        Err(E::SourceBytesInvalid)
    );
    let oversized = vec![b' '; PROVIDER_INTEGRATION_MAX_BYTES + 1];
    assert_eq!(
        compile_provider_integration(&oversized, &[]),
        Err(E::SourceBytesInvalid)
    );
    assert_eq!(compile_provider_integration(b"{", &[]), Err(E::JsonInvalid));
    let mut trailing = serde_json::to_vec(&manifest()).unwrap();
    trailing.extend_from_slice(b" {}");
    assert_eq!(
        compile_provider_integration(&trailing, &[]),
        Err(E::JsonInvalid)
    );
    refused(
        with("/schemaVersion", json!("guard.provider-integration.v2")),
        E::SchemaVersionUnsupported,
    );
}

#[test]
fn unknown_fields_and_repeated_keys_are_refused() {
    let mut unknown = manifest();
    unknown["extra"] = json!(true);
    refused(unknown, E::JsonInvalid);
    refused(
        with(
            "/capabilities/0/request/body/origin",
            json!({"fact": "target.origin", "value": "x"}),
        ),
        E::JsonInvalid,
    );
    refused(with("/verify", Value::Null), E::JsonInvalid);
    let text = serde_json::to_string(&manifest()).unwrap();
    let repeated_top = text.replacen(
        "\"name\":\"ExampleShield\"",
        "\"name\":\"ExampleShield\",\"name\":\"Other\"",
        1,
    );
    assert_eq!(
        compile_provider_integration(repeated_top.as_bytes(), &[]),
        Err(E::JsonInvalid)
    );
    let repeated_map = text.replacen(
        "\"clean\":\"ok\"",
        "\"clean\":\"ok\",\"clean\":\"danger\"",
        1,
    );
    assert_ne!(repeated_map, text);
    assert_eq!(
        compile_provider_integration(repeated_map.as_bytes(), &[]),
        Err(E::JsonInvalid)
    );
}

#[test]
fn identity_and_display_fields_are_checked() {
    refused(with("/id", json!("exampleshield")), E::IdInvalid);
    refused(with("/id", json!("provider.Example")), E::IdInvalid);
    refused(with("/name", json!(" ")), E::NameInvalid);
    refused(with("/name", json!("a\u{0007}b")), E::NameInvalid);
    refused(with("/summary", json!("x".repeat(201))), E::SummaryInvalid);
    refused(with("/publisher/name", json!("")), E::PublisherInvalid);
    // A name the user reads before trusting a provider carries no invisible or reordering marks.
    for mark in [
        '\u{00ad}', '\u{061c}', '\u{200b}', '\u{200e}', '\u{2028}', '\u{202e}', '\u{2060}',
        '\u{2066}', '\u{2069}', '\u{feff}',
    ] {
        let spoof = format!("ExampleShield{mark} Inc.");
        refused(with("/name", json!(spoof)), E::NameInvalid);
        refused(with("/summary", json!(spoof)), E::SummaryInvalid);
        refused(with("/publisher/name", json!(spoof)), E::PublisherInvalid);
    }
    assert!(compile(&with("/publisher/name", json!("Exämple Shield, Inc."))).is_ok());
    refused(
        with("/publisher/url", json!("http://exampleshield.example")),
        E::PublisherInvalid,
    );
    refused(with("/surfaces", json!([])), E::SurfacesInvalid);
    refused(
        with("/surfaces", json!(["browser", "browser"])),
        E::SurfacesInvalid,
    );
    refused(with("/surfaces", json!(["mail"])), E::SurfacesInvalid);
    let mut icon = manifest();
    icon["icon"] = json!("https://exampleshield.example/icon.png");
    refused(icon.clone(), E::IconInvalid);
    for unknown in [
        "FiShield",
        "NotARealIconComponent",
        "HiMiniBoltX",
        "himinibolt",
        "",
    ] {
        icon["icon"] = json!(unknown);
        refused(icon.clone(), E::IconInvalid);
    }
    for known in ["none", "HiMiniGlobeAlt", "HiMiniCloud"] {
        icon["icon"] = json!(known);
        assert!(compile(&icon).is_ok(), "{known}");
    }
    refused(
        with("/privacyUrl", json!("https://exampleshield.example/p?x=1")),
        E::PolicyUrlInvalid,
    );
    refused(
        with("/termsUrl", json!("exampleshield.example/terms")),
        E::PolicyUrlInvalid,
    );
    refused(
        with(
            "/auth/obtainUrl",
            json!("http://exampleshield.example/keys"),
        ),
        E::PolicyUrlInvalid,
    );
}

#[test]
fn only_maintainers_can_mark_a_provider_verified() {
    let verified = with("/publisher/verified", json!(true));
    refused(verified.clone(), E::PublisherVerificationUnproven);
    let bytes = serde_json::to_vec(&verified).unwrap();
    assert!(
        compile_provider_integration(&bytes, &[ID])
            .unwrap()
            .verified
    );
    assert_eq!(
        compile_provider_integration(&bytes, &["provider.other"]),
        Err(E::PublisherVerificationUnproven)
    );
}

#[test]
fn auth_is_one_declared_header_with_a_bounded_key() {
    refused(
        with("/auth/kind", json!("signed-enrollment")),
        E::AuthKindReserved,
    );
    for kind in ["oauth", "basic", "query", ""] {
        refused(with("/auth/kind", json!(kind)), E::AuthKindUnsupported);
    }
    for header in [
        "",
        "X-Provider-Key",
        "x provider",
        "-x",
        "cookie",
        "host",
        "content-type",
        "user-agent",
        "proxy-authorization",
        "sec-fetch-site",
        "x-forwarded-for",
    ] {
        refused(with("/auth/header", json!(header)), E::AuthHeaderInvalid);
    }
    refused(
        with("/auth/keyFormat/minLength", json!(8)),
        E::KeyFormatInvalid,
    );
    refused(
        with("/auth/keyFormat/maxLength", json!(4096)),
        E::KeyFormatInvalid,
    );
    refused(
        with("/auth/keyFormat/maxLength", json!(20)),
        E::KeyFormatInvalid,
    );
    refused(
        with("/auth/keyFormat/charset", json!("any")),
        E::KeyFormatInvalid,
    );
}

#[test]
fn hosts_are_exact_public_https_names() {
    refused(with("/hosts", json!([])), E::HostsInvalid);
    refused(
        with(
            "/hosts",
            json!(["api.exampleshield.example", "api.exampleshield.example"]),
        ),
        E::HostsInvalid,
    );
    refused(
        with(
            "/hosts",
            json!([
                "a.example.com",
                "b.example.com",
                "c.example.com",
                "d.example.com",
                "e.example.com"
            ]),
        ),
        E::HostsInvalid,
    );
    for host in [
        "*.exampleshield.example",
        "api.exampleshield.example:443",
        "API.exampleshield.example",
        "203.0.113.9",
        "[2001:db8::1]",
        "0x7f.1",
        "localhost",
        "api.localhost",
        "exampleshield",
        "api.exampleshield.local",
        "api.exampleshield.internal",
        "api.exampleshield.test",
        "nas.home.arpa",
        "exampleshield.github.io",
        "exampleshield.vercel.app",
        "https://api.exampleshield.example",
        "api.exampleshield.example/v1",
    ] {
        refused(with("/hosts", json!([host])), E::HostInvalid);
    }
}

#[test]
fn a_set_refuses_two_manifests_with_one_id() {
    let bytes = serde_json::to_vec(&manifest()).unwrap();
    assert_eq!(
        compile_provider_integration_set(&[&bytes, &bytes], &[]),
        Err(E::ProviderIdDuplicate)
    );
    let other = serde_json::to_vec(&with("/id", json!("provider.exampleguard"))).unwrap();
    assert_eq!(
        compile_provider_integration_set(&[&bytes, &other], &[])
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn a_contributed_manifest_cannot_claim_the_fixture_prefix() {
    let shipped = serde_json::to_vec(&manifest()).unwrap();
    let fixture = serde_json::to_vec(&with("/id", json!("provider.fixture-shield"))).unwrap();
    assert_eq!(
        compile_provider_integration(&fixture, &[]).map(|compiled| compiled.id),
        Ok("provider.fixture-shield".to_owned())
    );
    assert_eq!(
        compile_contributed_provider_integration_set(&[&shipped, &fixture], &[]),
        Err(E::FixtureIdContributed)
    );
    assert_eq!(
        compile_contributed_provider_integration_set(&[&fixture], &[]),
        Err(E::FixtureIdContributed)
    );
    let lookalike = serde_json::to_vec(&with("/id", json!("provider.fixtures"))).unwrap();
    assert_eq!(
        compile_contributed_provider_integration_set(&[&shipped, &lookalike], &[])
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn every_refusal_has_a_distinct_stable_code() {
    let all = [
        E::SourceBytesInvalid,
        E::JsonInvalid,
        E::SchemaVersionUnsupported,
        E::IdInvalid,
        E::NameInvalid,
        E::SummaryInvalid,
        E::PublisherInvalid,
        E::PublisherVerificationUnproven,
        E::SurfacesInvalid,
        E::AuthKindUnsupported,
        E::AuthKindReserved,
        E::AuthHeaderInvalid,
        E::KeyFormatInvalid,
        E::HostsInvalid,
        E::HostInvalid,
        E::CapabilitiesInvalid,
        E::CapabilityUnknown,
        E::CapabilityDuplicate,
        E::RequestMethodInvalid,
        E::RequestHostInvalid,
        E::RequestPathInvalid,
        E::RequestBodyInvalid,
        E::FactUnknown,
        E::SharesMismatch,
        E::ResponsePointerInvalid,
        E::VerdictMapInvalid,
        E::ReasonCodesInvalid,
        E::ReasonLabelInvalid,
        E::TtlInvalid,
        E::VerifyInvalid,
        E::LimitsInvalid,
        E::PolicyUrlInvalid,
        E::IconInvalid,
        E::ProviderIdDuplicate,
        E::FixtureIdContributed,
    ];
    let codes: BTreeSet<&str> = all.iter().map(|error| error.code()).collect();
    assert_eq!(codes.len(), all.len());
    assert!(codes
        .iter()
        .all(|code| code.starts_with("provider_integration_")));
}
