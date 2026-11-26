use serde_json::{json, Value};

use super::tests::{compile, manifest, refused, with, without};
use super::*;

#[test]
fn requests_render_a_literal_path_on_a_declared_host() {
    for path in [
        "v1/guard/origin",
        "/v1/guard/origin?key=abc",
        "/v1/guard/origin#x",
        "/v1/{origin}",
        "/v1/../admin",
        "/v1//origin",
        "/v1/%2e%2e",
        "/v1/guard origin",
        "/v1\\origin",
    ] {
        refused(
            with("/capabilities/0/request/path", json!(path)),
            E::RequestPathInvalid,
        );
    }
    refused(
        with("/capabilities/0/request/method", json!("PUT")),
        E::RequestMethodInvalid,
    );
    refused(
        with("/capabilities/0/request/method", json!("post")),
        E::RequestMethodInvalid,
    );
    let mut undeclared = manifest();
    undeclared["capabilities"][0]["request"]["host"] = json!("other.exampleshield.example");
    refused(undeclared, E::RequestHostInvalid);
    let mut two_hosts = with(
        "/hosts",
        json!(["api.exampleshield.example", "eu.exampleshield.example"]),
    );
    refused(two_hosts.clone(), E::RequestHostInvalid);
    two_hosts["capabilities"][0]["request"]["host"] = json!("eu.exampleshield.example");
    two_hosts["verify"]["host"] = json!("api.exampleshield.example");
    let compiled = compile(&two_hosts).unwrap();
    assert_eq!(
        compiled.capabilities[0].request.url(),
        "https://eu.exampleshield.example/v1/guard/origin"
    );
}

#[test]
fn request_bodies_carry_closed_facts_only() {
    refused(
        with("/capabilities/0/request/method", json!("GET")),
        E::RequestBodyInvalid,
    );
    refused(
        without("/capabilities/0/request", "body"),
        E::RequestBodyInvalid,
    );
    refused(
        with("/capabilities/0/request/body", json!({})),
        E::RequestBodyInvalid,
    );
    refused(
        with(
            "/capabilities/0/request/body",
            json!({"origin": "https://shop.example.com"}),
        ),
        E::JsonInvalid,
    );
    refused(
        with(
            "/capabilities/0/request/body",
            json!({"origin": {"fact": "target.url"}}),
        ),
        E::FactUnknown,
    );
    refused(
        with(
            "/capabilities/0/request/body",
            json!({"bad-name": {"fact": "target.origin"}}),
        ),
        E::RequestBodyInvalid,
    );
    let many: serde_json::Map<String, Value> = (0..17)
        .map(|index| (format!("f{index}"), json!({"fact": "target.origin"})))
        .collect();
    refused(
        with("/capabilities/0/request/body", Value::Object(many)),
        E::RequestBodyInvalid,
    );
}

#[test]
fn shares_equals_the_facts_the_request_uses() {
    refused(with("/capabilities/0/shares", json!([])), E::SharesMismatch);
    refused(
        with(
            "/capabilities/0/shares",
            json!(["target.origin", "target.site_group"]),
        ),
        E::SharesMismatch,
    );
    refused(
        with(
            "/capabilities/0/shares",
            json!(["target.origin", "target.origin"]),
        ),
        E::SharesMismatch,
    );
    refused(
        with("/capabilities/0/shares", json!(["page.text"])),
        E::FactUnknown,
    );
    let mut two = manifest();
    two["capabilities"][0]["request"]["body"]["group"] = json!({"fact": "target.site_group"});
    refused(two.clone(), E::SharesMismatch);
    two["capabilities"][0]["shares"] = json!(["target.site_group", "target.origin"]);
    assert!(compile(&two).is_ok());
}

#[test]
fn capabilities_are_the_closed_list_once_each() {
    refused(with("/capabilities", json!([])), E::CapabilitiesInvalid);
    refused(
        with("/capabilities/0/id", json!("browser.everything")),
        E::CapabilityUnknown,
    );
    let mut twice = manifest();
    let first = twice["capabilities"][0].clone();
    twice["capabilities"].as_array_mut().unwrap().push(first);
    refused(twice, E::CapabilityDuplicate);
}

#[test]
fn responses_are_read_through_pointers_onto_closed_verdicts() {
    for pointer in ["verdict", "/a~2b", "/a~", "/a\u{0001}"] {
        refused(
            with("/capabilities/0/response/verdict/pointer", json!(pointer)),
            E::ResponsePointerInvalid,
        );
        refused(
            with(
                "/capabilities/0/response/reasonCodes/pointer",
                json!(pointer),
            ),
            E::ResponsePointerInvalid,
        );
        refused(
            with(
                "/capabilities/0/response/ttlSeconds/pointer",
                json!(pointer),
            ),
            E::ResponsePointerInvalid,
        );
    }
    refused(
        with("/capabilities/0/response/verdict/map", json!({})),
        E::VerdictMapInvalid,
    );
    refused(
        with(
            "/capabilities/0/response/verdict/map",
            json!({"clean": "allow"}),
        ),
        E::VerdictMapInvalid,
    );
    refused(
        with(
            "/capabilities/0/response/verdict/map",
            json!({"has space": "ok"}),
        ),
        E::VerdictMapInvalid,
    );
    let many: serde_json::Map<String, Value> = (0..17)
        .map(|index| (format!("v{index}"), json!("caution")))
        .collect();
    refused(
        with("/capabilities/0/response/verdict/map", Value::Object(many)),
        E::VerdictMapInvalid,
    );
}

#[test]
fn reason_codes_are_bounded_and_labels_are_safe_text() {
    refused(
        with("/capabilities/0/response/reasonCodes/allow", json!([])),
        E::ReasonCodesInvalid,
    );
    refused(
        with(
            "/capabilities/0/response/reasonCodes/allow",
            json!(["Phishing"]),
        ),
        E::ReasonCodesInvalid,
    );
    refused(
        with(
            "/capabilities/0/response/reasonCodes/allow",
            json!(["a", "a"]),
        ),
        E::ReasonCodesInvalid,
    );
    let many: Vec<String> = (0..33).map(|index| format!("code_{index}")).collect();
    refused(
        with("/capabilities/0/response/reasonCodes/allow", json!(many)),
        E::ReasonCodesInvalid,
    );
    for label in [
        "",
        "<b>bad</b>",
        "line\u{2028}break",
        "rtl\u{202e}text",
        "zero\u{200b}width",
        "x".repeat(81).as_str(),
    ] {
        refused(
            with(
                "/capabilities/0/response/reasonCodes/labels/phishing",
                json!(label),
            ),
            E::ReasonLabelInvalid,
        );
    }
    refused(
        with(
            "/capabilities/0/response/reasonCodes/labels",
            json!({"spam": "Sends spam"}),
        ),
        E::ReasonLabelInvalid,
    );
}

#[test]
fn ttl_and_limits_are_capped_by_guard() {
    refused(
        with("/capabilities/0/response/ttlSeconds/min", json!(10)),
        E::TtlInvalid,
    );
    refused(
        with("/capabilities/0/response/ttlSeconds/max", json!(86_401)),
        E::TtlInvalid,
    );
    refused(
        with("/capabilities/0/response/ttlSeconds/min", json!(90_000)),
        E::TtlInvalid,
    );
    refused(with("/limits/timeoutMs", json!(0)), E::LimitsInvalid);
    refused(with("/limits/timeoutMs", json!(2_001)), E::LimitsInvalid);
    refused(
        with("/limits/maxResponseBytes", json!(65_537)),
        E::LimitsInvalid,
    );
    refused(
        with("/limits/maxRequestsPerMinute", json!(61)),
        E::LimitsInvalid,
    );
    let capped = with(
        "/limits",
        json!({"timeoutMs": 2000, "maxResponseBytes": 65536, "maxRequestsPerMinute": 60}),
    );
    assert!(compile(&capped).is_ok());
}

#[test]
fn verify_is_a_bodiless_request_on_a_declared_host() {
    refused(
        with(
            "/verify",
            json!({"method": "POST", "path": "/v1/key", "body": {"o": {"fact": "guard.version"}}}),
        ),
        E::VerifyInvalid,
    );
    refused(
        with("/verify/path", json!("/v1/key?token=1")),
        E::RequestPathInvalid,
    );
    assert!(compile(&without("", "verify")).is_ok());
}
