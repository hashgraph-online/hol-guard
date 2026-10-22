use super::tests::SOURCE;
use crate::pack_lifecycle::evaluate as dispatch;
use serde_json::{json, Value};

const SUBJECT: &str = "extension-distribution.v2.json";
const DIGEST: &str = "cdd0fb6a3cf407fc3947a5423747b7e5409479db5b02b1c3d441d9d9a4b501ac";
const TYPE: &str = "application/vnd.in-toto+json";
const BUILD: &str = "/predicate/buildDefinition";
const WORKFLOW: &str = "/predicate/buildDefinition/externalParameters/workflow";

fn statement() -> Value {
    json!({
        "_type": "https://in-toto.io/Statement/v1",
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"name": SUBJECT, "digest": {"sha256": DIGEST}}],
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {"workflow": {
                    "repository": "https://github.com/hashgraph-online/hol-guard",
                    "path": ".github/workflows/extension-artifact-regen.yml",
                    "ref": "refs/heads/main",
                }},
                "resolvedDependencies": [{
                    "uri": "git+https://github.com/hashgraph-online/hol-guard@refs/heads/main",
                    "digest": {"gitCommit": SOURCE},
                }],
            },
            "runDetails": {"builder": {"id": concat!(
                "https://github.com/hashgraph-online/hol-guard/",
                ".github/workflows/extension-artifact-regen.yml@refs/heads/main"
            )}},
        },
    })
}

fn attest_text(
    payload: &str,
    content_type: &str,
    subject: &str,
    digest: &str,
) -> Result<Value, String> {
    dispatch(&json!({
        "kind": "distribution", "operation": "provenance-statement", "content_type": content_type,
        "payload": payload, "subject": subject, "digest": digest, "source": SOURCE,
    }))
}

fn attest(value: &Value) -> Result<Value, String> {
    attest_text(&value.to_string(), TYPE, SUBJECT, DIGEST)
}

fn with(pointer: &str, to: Value) -> Value {
    let mut value = statement();
    *value.pointer_mut(pointer).unwrap() = to;
    value
}

fn expect(value: Value, code: &str, why: &str) {
    assert_eq!(attest(&value), Err(code.into()), "{why}");
}

#[test]
fn a_statement_for_this_workflow_attests_only_its_own_subject() {
    assert_eq!(attest(&statement()), Ok(json!({"attested": true})));
    let text = statement().to_string();
    let no = Ok(json!({"attested": false}));
    assert_eq!(attest_text(&text, TYPE, SUBJECT, &"0".repeat(64)), no);
    assert_eq!(attest_text(&text, TYPE, "other.json", DIGEST), no);
    let mut extra = statement();
    extra["subject"][0]["digest"]["sha512"] = json!("0");
    assert_eq!(attest(&extra), no);
}

#[test]
fn a_statement_from_another_workflow_or_source_is_refused() {
    let builder = "distribution_builder_differs";
    let source = "distribution_source_differs";
    let dependency = format!("{BUILD}/resolvedDependencies/0/digest");
    let repository = format!("{WORKFLOW}/repository");
    let reference = format!("{WORKFLOW}/ref");
    let commit = format!("{dependency}/gitCommit");
    let mut workflow =
        statement()["predicate"]["buildDefinition"]["externalParameters"]["workflow"].clone();
    workflow["inputs"] = json!({});
    let pinned = json!({"gitCommit": SOURCE, "sha256": "0"});
    let cases = [
        (
            "/_type",
            json!("other"),
            "distribution_statement_type_invalid",
        ),
        (
            "/predicateType",
            json!("other"),
            "distribution_statement_type_invalid",
        ),
        ("/predicate", json!([]), "distribution_predicate_invalid"),
        (
            "/predicate/runDetails",
            json!(1),
            "distribution_build_definition_invalid",
        ),
        (
            "/predicate/buildDefinition/externalParameters",
            json!(1),
            "distribution_build_definition_invalid",
        ),
        (
            "/predicate/buildDefinition/buildType",
            json!("other"),
            builder,
        ),
        ("/predicate/runDetails/builder/id", json!("other"), builder),
        (
            &repository,
            json!("https://github.com/example/other"),
            builder,
        ),
        (&reference, json!("refs/heads/other"), builder),
        (WORKFLOW, workflow, builder),
        (
            "/predicate/buildDefinition/resolvedDependencies",
            json!({}),
            "distribution_dependencies_invalid",
        ),
        (
            "/predicate/buildDefinition/resolvedDependencies",
            json!([]),
            source,
        ),
        (&commit, json!("0".repeat(40)), source),
        (dependency.as_str(), pinned, source),
        ("/subject", json!([]), "distribution_subject_count_invalid"),
        (
            "/subject",
            Value::Array(vec![json!({}); 65]),
            "distribution_subject_count_invalid",
        ),
    ];
    for (pointer, to, code) in cases {
        expect(with(pointer, to), code, pointer);
    }
    let mut twice = statement();
    let row = twice["predicate"]["buildDefinition"]["resolvedDependencies"][0].clone();
    twice["predicate"]["buildDefinition"]["resolvedDependencies"]
        .as_array_mut()
        .unwrap()
        .push(row);
    expect(twice, source, "source twice");
    let mut twice = statement();
    let row = twice["subject"][0].clone();
    twice["subject"].as_array_mut().unwrap().push(row);
    expect(twice, "distribution_duplicate_subjects", "subject twice");
    let mut missing = statement();
    missing["predicate"]
        .as_object_mut()
        .unwrap()
        .remove("runDetails");
    expect(missing, "distribution_build_definition_invalid", "no run");
}

#[test]
fn a_statement_payload_is_checked_before_it_is_parsed() {
    let text = statement().to_string();
    let payload = "distribution_statement_payload_invalid";
    assert_eq!(
        attest_text(&text, "application/json", SUBJECT, DIGEST),
        Err(payload.into())
    );
    let big = format!("{{\"a\":\"{}\"}}", "x".repeat(1024 * 1024));
    assert_eq!(
        attest_text(&big, TYPE, SUBJECT, DIGEST),
        Err(payload.into())
    );
    let duplicate = attest_text(r#"{"_type":1,"_type":2}"#, TYPE, SUBJECT, DIGEST);
    assert_eq!(duplicate, Err("distribution_duplicate_field".into()));
    let bad = attest_text("[", TYPE, SUBJECT, DIGEST);
    assert_eq!(bad, Err("distribution_encoding_invalid".into()));
    let bad = attest_text(&text, TYPE, SUBJECT, "short");
    assert_eq!(bad, Err("distribution_request_invalid".into()));
}

#[test]
fn an_escape_heavy_statement_within_its_bound_reaches_the_validator() {
    // Every quote and backslash doubles when the request is encoded.
    let payload = format!("\"{}\"", "\\\"".repeat(300 * 1024));
    let request = json!({
        "kind": "distribution", "operation": "provenance-statement", "content_type": TYPE,
        "payload": payload, "subject": SUBJECT, "digest": DIGEST, "source": SOURCE,
    })
    .to_string();
    assert!(payload.len() < 1024 * 1024 && request.len() > 1024 * 1024);
    assert_eq!(
        crate::pack_lifecycle::run(request.as_bytes()),
        Err("distribution_statement_type_invalid".into())
    );
}
