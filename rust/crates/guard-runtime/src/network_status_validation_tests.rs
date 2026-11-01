use super::*;

const NOW: u64 = 1_000_000_000_000;

fn inactive() -> Value {
    json!({
        "schema": "guard.network-status.v1",
        "host_platform": "linux",
        "effective_grade": "unavailable",
        "independently_observed_grade": "unavailable",
        "protection_active": false,
        "independently_observed": false,
        "reason_code": "no-verified-installed-backend",
        "backends": [{
            "backend_id": "linux.oci-proxy",
            "platform": "linux",
            "supported": true,
            "installed": false,
            "verified": false,
            "active": false,
            "observed": false,
            "advertised_maximum_grade": "proxy-only",
            "effective_grade": "unavailable",
            "production_ready": false,
            "requires_privilege": true,
            "reason_code": "no-live-provider-probe",
            "reference_reason_code": "alpha-not-validated",
        }],
    })
}

fn active() -> Value {
    let mut status = inactive();
    let backend = &mut status["backends"][0];
    for flag in ["installed", "verified", "active", "production_ready"] {
        backend[flag] = json!(true);
    }
    backend["effective_grade"] = json!("proxy-only");
    status["effective_grade"] = json!("proxy-only");
    status["protection_active"] = json!(true);
    status["supervisor"] = json!({
        "phase": "healthy",
        "backend_id": "linux.oci-proxy",
        "backend_digest": "a".repeat(64),
        "effective_grade": "proxy-only",
        "healthy_until_epoch_ms": 2_000_000_000_000_u64,
        "retry_attempt": 0,
        "next_retry_seconds": 0.0,
        "permits_enforcement": true,
        "independently_observed": false,
    });
    status
}

fn ask(status: &Value) -> Value {
    let request = json!({ "schema": SCHEMA, "status": status, "now_epoch_ms": NOW });
    let bytes = run_command(request.to_string().as_bytes()).expect("answered");
    serde_json::from_slice(&bytes).expect("answer is JSON")
}

fn error(status: &Value) -> String {
    ask(status)["error"].as_str().expect("refused").to_owned()
}

#[test]
fn an_inactive_status_projects_in_presentation_order() {
    let mut status = inactive();
    status["unrelated"] = json!("dropped");
    status["backends"][0]["secret"] = json!("dropped");
    let request = json!({ "schema": SCHEMA, "status": status, "now_epoch_ms": NOW });
    let text = String::from_utf8(run_command(request.to_string().as_bytes()).expect("answered"))
        .expect("utf-8");
    assert!(
        text.starts_with(
            "{\"status\":{\"schema\":\"guard.network-status.v1\",\"host_platform\":\"linux\",\"effective_grade\":"
        ),
        "{text}"
    );
    assert!(text.contains(
        "\"backends\":[{\"backend_id\":\"linux.oci-proxy\",\"platform\":\"linux\",\"supported\":true"
    ));
    assert!(!text.contains("dropped"));
    assert!(!text.contains("supervisor"));
}

#[test]
fn an_active_status_keeps_its_supervisor_proof() {
    let answer = ask(&active());
    assert_eq!(answer["status"]["protection_active"], true);
    assert_eq!(answer["status"]["supervisor"]["retry_attempt"], 0);
    assert_eq!(answer["status"]["supervisor"]["next_retry_seconds"], 0.0);
}

#[test]
fn an_active_backend_must_be_production_ready_and_within_its_grade() {
    let mut status = active();
    status["backends"][0]["production_ready"] = json!(false);
    assert!(error(&status).contains("production ready"));

    let mut status = active();
    status["backends"][0]["effective_grade"] = json!("destination-enforced");
    status["effective_grade"] = json!("destination-enforced");
    status["supervisor"]["effective_grade"] = json!("destination-enforced");
    assert!(error(&status).contains("advertised grade"));
}

#[test]
fn an_inactive_backend_cannot_enforce() {
    let mut status = inactive();
    status["backends"][0]["effective_grade"] = json!("proxy-only");
    assert_eq!(error(&status), "inactive network backend cannot enforce");
}

#[test]
fn the_supervisor_must_prove_live_protection() {
    let mut status = active();
    status["supervisor"]["healthy_until_epoch_ms"] = json!(NOW);
    assert_eq!(
        error(&status),
        "network supervisor does not prove protection"
    );

    let mut status = active();
    status["supervisor"]["backend_id"] = json!("linux.other");
    assert_eq!(
        error(&status),
        "network supervisor does not prove protection"
    );

    let mut status = active();
    status["supervisor"] = Value::Null;
    assert_eq!(
        error(&status),
        "active network protection requires supervisor proof"
    );

    let mut status = active();
    status["supervisor"]
        .as_object_mut()
        .expect("object")
        .remove("retry_attempt");
    assert_eq!(error(&status), "network supervisor is incomplete");
}

#[test]
fn supervisor_numbers_are_exact() {
    for (field, value, message) in [
        (
            "retry_attempt",
            json!(1.0),
            "network supervisor retry is invalid",
        ),
        (
            "retry_attempt",
            json!(-1),
            "network supervisor retry is invalid",
        ),
        (
            "retry_attempt",
            json!(true),
            "network supervisor retry is invalid",
        ),
        (
            "next_retry_seconds",
            json!(-0.5),
            "network supervisor delay is invalid",
        ),
        (
            "next_retry_seconds",
            json!("1"),
            "network supervisor delay is invalid",
        ),
        (
            "healthy_until_epoch_ms",
            json!(1.5),
            "network supervisor expiry is invalid",
        ),
        (
            "healthy_until_epoch_ms",
            json!(-1),
            "network supervisor expiry is invalid",
        ),
        (
            "backend_digest",
            json!("A".repeat(64)),
            "network supervisor digest is invalid",
        ),
        (
            "permits_enforcement",
            json!(1),
            "network supervisor boolean is invalid",
        ),
    ] {
        let mut status = active();
        status["supervisor"][field] = value;
        assert_eq!(error(&status), message, "{field}");
    }
    let mut status = active();
    status["supervisor"]["healthy_until_epoch_ms"] = json!(Value::Null);
    assert_eq!(
        error(&status),
        "network supervisor does not prove protection"
    );
}

#[test]
fn observer_summaries_must_agree() {
    let mut status = inactive();
    status["independently_observed"] = json!(true);
    assert_eq!(error(&status), "network observer summary is inconsistent");

    let mut status = inactive();
    status["backends"][0]["observed"] = json!(true);
    assert_eq!(
        error(&status),
        "network backend observer summary is inconsistent"
    );

    let mut status = inactive();
    status["backends"][0]["observed"] = json!(true);
    status["backends"][0]["effective_grade"] = json!("observe");
    status["independently_observed"] = json!(true);
    status["independently_observed_grade"] = json!("observe");
    assert_eq!(ask(&status)["status"]["independently_observed"], true);
    status["independently_observed_grade"] = json!("deny-all");
    assert_eq!(error(&status), "network observer grade is inconsistent");
}

#[test]
fn header_and_backend_shapes_are_strict() {
    for (field, value, message) in [
        (
            "schema",
            json!("guard.network-status.v2"),
            "network status schema is invalid",
        ),
        (
            "host_platform",
            json!("plan9"),
            "network status enum is invalid",
        ),
        (
            "host_platform",
            Value::Null,
            "network status enum must be a string",
        ),
        (
            "protection_active",
            json!(0),
            "network status boolean is invalid",
        ),
        (
            "reason_code",
            json!("Bad Reason"),
            "network status reason is invalid",
        ),
        ("backends", json!({}), "network status backends are invalid"),
    ] {
        let mut status = inactive();
        status[field] = value;
        assert_eq!(error(&status), message, "{field}");
    }
    let mut status = inactive();
    status["host_platform"] = json!("unsupported");
    assert_eq!(ask(&status)["status"]["host_platform"], "unsupported");

    let mut status = inactive();
    let backend = status["backends"][0].clone();
    status["backends"] = json!([backend.clone(), backend]);
    assert_eq!(error(&status), "network status backend id is duplicated");

    let mut status = inactive();
    status["backends"][0]["verified"] = json!(true);
    assert_eq!(error(&status), "verified network backend must be installed");
}

#[test]
fn identifiers_follow_the_safe_pattern() {
    let longest = "a".repeat(128);
    let too_long = "a".repeat(129);
    for good in ["a", "linux.oci-proxy", "a1_b2.c3", longest.as_str()] {
        assert!(is_safe_identifier(Some(&json!(good))), "{good}");
    }
    for bad in [
        "",
        "1a",
        "a.",
        "a..b",
        "a-.b",
        "A",
        "a b",
        too_long.as_str(),
    ] {
        assert!(!is_safe_identifier(Some(&json!(bad))), "{bad}");
    }
}

#[test]
fn the_legacy_policy_is_projected_strictly() {
    let mut status = inactive();
    status["legacy_domain_policy"] = json!({"sandbox_required": true, "action": "approve", "x": 1});
    assert!(String::from_utf8(
        run_command(
            json!({ "schema": SCHEMA, "status": status, "now_epoch_ms": NOW })
                .to_string()
                .as_bytes()
        )
        .expect("answered")
    )
    .expect("utf-8")
    .ends_with("\"legacy_domain_policy\":{\"action\":\"approve\",\"sandbox_required\":true}}}"));

    status["legacy_domain_policy"]["action"] = json!("maybe");
    assert_eq!(error(&status), "legacy network domain action is invalid");
    status["legacy_domain_policy"]["action"] = json!(1);
    assert_eq!(error(&status), "legacy network domain policy is invalid");
}

#[test]
fn requests_are_validated() {
    for request in [
        json!({ "schema": "network-status-validation.v0", "status": {}, "now_epoch_ms": 0 }),
        json!({ "schema": SCHEMA, "status": {}, "now_epoch_ms": -1 }),
        json!({ "schema": SCHEMA, "status": {}, "now_epoch_ms": 0, "extra": true }),
    ] {
        assert_eq!(
            run_command(request.to_string().as_bytes()).expect_err("refused"),
            "network_status_validation_request_invalid"
        );
    }
}
