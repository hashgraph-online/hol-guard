use super::*;
use guard_contracts::INVENTORY_URL_REDACTION_FEATURE;
use serde_json::{json, Value};

fn request(tasks: Vec<InventoryUrlTaskV1>) -> InventoryUrlRedactionRequestV1 {
    InventoryUrlRedactionRequestV1 {
        schema: INVENTORY_URL_REDACTION_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        tasks,
    }
}

fn reply(request: &InventoryUrlRedactionRequestV1) -> Value {
    let encoded = evaluate_inventory_url_redaction(request).expect("reply");
    serde_json::from_slice(&encoded).expect("json reply")
}

fn answers(tasks: Vec<InventoryUrlTaskV1>) -> Value {
    reply(&request(tasks))["answers"].clone()
}

fn url(value: &str) -> InventoryUrlTaskV1 {
    InventoryUrlTaskV1::RedactUrl {
        value: value.to_owned(),
    }
}

#[test]
fn a_url_loses_its_userinfo_and_its_sensitive_query_values() {
    assert_eq!(
        answers(vec![
            url("https://user:hunter2@example.test/path"),
            url("https://example.test/path?token=abc123&page=2"),
        ]),
        json!([
            {"kind": "redact_url", "value": "https://example.test/path"},
            {
                "kind": "redact_url",
                "value": "https://example.test/path?token=redacted&page=2"
            },
        ])
    );
}

#[test]
fn a_url_the_parser_refuses_is_redacted_whole_rather_than_echoed() {
    assert_eq!(
        answers(vec![url("https://[::1/unclosed")]),
        json!([{"kind": "redact_url", "value": "malformed_url_redacted"}])
    );
}

#[test]
fn headers_report_presence_per_name_and_never_a_value() {
    assert_eq!(
        answers(vec![InventoryUrlTaskV1::RedactHeaders {
            header_names: vec![
                "Authorization".to_owned(),
                "X-Api-Key".to_owned(),
                "Cookie".to_owned(),
            ],
        }]),
        json!([{
            "kind": "redact_headers",
            "headers": [
                ["authorization", "present_redacted"],
                ["x-api-key", "present_redacted"],
                ["cookie", "present"],
            ],
        }])
    );
}

#[test]
fn an_endpoint_is_classified_without_a_network_request() {
    let classify = |value: Option<&str>| InventoryUrlTaskV1::ClassifyEndpointHost {
        value: value.map(str::to_owned),
    };
    assert_eq!(
        answers(vec![
            classify(None),
            classify(Some("http://LOCALHOST/api")),
            classify(Some("https://10.0.0.5/api")),
            classify(Some("https://example.test/api")),
        ]),
        json!([
            {"kind": "classify_endpoint_host", "host_class": "none"},
            {"kind": "classify_endpoint_host", "host_class": "local_loopback"},
            {"kind": "classify_endpoint_host", "host_class": "local_private"},
            {"kind": "classify_endpoint_host", "host_class": "remote_public"},
        ])
    );
}

fn command(value: &str, workspace: Option<&str>) -> InventoryUrlTaskV1 {
    InventoryUrlTaskV1::RedactCommandValue {
        value: value.to_owned(),
        home_dir: "/tmp/hgparity-home".to_owned(),
        workspace_dir: workspace.map(str::to_owned),
        cwd: "/tmp/hgparity-home".to_owned(),
    }
}

fn known_path(value: &str, workspace: Option<&str>) -> InventoryUrlTaskV1 {
    InventoryUrlTaskV1::RedactKnownPath {
        value: value.to_owned(),
        home_dir: "/tmp/hgparity-home".to_owned(),
        workspace_dir: workspace.map(str::to_owned),
        cwd: "/tmp/hgparity-home".to_owned(),
    }
}

#[test]
fn a_command_loses_its_credential_arguments_and_its_private_paths() {
    assert_eq!(
        answers(vec![
            command("npx server --api-key abc123 --port 7", None),
            command("run secret=zzz PASSWORD=yyy", None),
            command(
                "node /tmp/hgparity-home/work/server.js --token xyz",
                Some("/tmp/hgparity-home/work"),
            ),
        ]),
        json!([
            {
                "kind": "redact_command_value",
                "value": "npx server --api-key redacted --port 7"
            },
            {
                "kind": "redact_command_value",
                "value": "run secret=redacted PASSWORD=redacted"
            },
            {
                "kind": "redact_command_value",
                "value": "node {home}/work/server.js --token redacted"
            },
        ])
    );
}

#[test]
fn a_path_is_labelled_against_the_roots_the_caller_sent_not_the_residents_own() {
    assert_eq!(
        answers(vec![
            known_path("/tmp/hgparity-home/x/y.txt", None),
            known_path(
                "/tmp/hgparity-home/work/a/b.txt",
                Some("/tmp/hgparity-home/work"),
            ),
            known_path("/etc/hosts", Some("/tmp/hgparity-home/work")),
            known_path("rel/path.txt", Some("/tmp/hgparity-home/work")),
        ]),
        json!([
            {"kind": "redact_known_path", "value": "{home}/x/y.txt"},
            {"kind": "redact_known_path", "value": "{home}/work/a/b.txt"},
            {"kind": "redact_known_path", "value": "hosts"},
            {"kind": "redact_known_path", "value": "rel/path.txt"},
        ])
    );
}

#[test]
fn a_command_url_is_redacted_by_the_same_pass_rather_than_a_second_request() {
    assert_eq!(
        answers(vec![command(
            "curl https://user:hunter2@example.test/x?token=abc123&page=2",
            None,
        )]),
        json!([{
            "kind": "redact_command_value",
            "value": "curl https://example.test/x?token=redacted"
        }])
    );
}

#[test]
fn answers_come_back_in_the_order_the_tasks_were_sent() {
    let mixed = answers(vec![
        url("https://example.test/first"),
        InventoryUrlTaskV1::ClassifyEndpointHost {
            value: Some("http://127.0.0.1/second".to_owned()),
        },
        InventoryUrlTaskV1::RedactHeaders {
            header_names: vec!["Accept".to_owned()],
        },
    ]);
    let kinds: Vec<&str> = mixed
        .as_array()
        .expect("answers")
        .iter()
        .map(|answer| answer["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(
        kinds,
        ["redact_url", "classify_endpoint_host", "redact_headers"]
    );
}

#[test]
fn an_empty_pass_is_answered_rather_than_refused() {
    assert_eq!(answers(vec![]), json!([]));
}

#[test]
fn more_tasks_than_the_bound_allows_are_refused() {
    let tasks = vec![url("https://example.test/x"); INVENTORY_URL_REDACTION_MAX_TASKS + 1];
    assert_eq!(
        evaluate_inventory_url_redaction(&request(tasks)),
        Err("native_inventory_url_redaction_invalid".to_owned())
    );
}

#[test]
fn a_foreign_schema_is_refused() {
    let mut foreign = request(vec![]);
    foreign.schema = "guard-something-else.v1".to_owned();
    assert_eq!(
        evaluate_inventory_url_redaction(&foreign),
        Err("native_inventory_url_redaction_schema_mismatch".to_owned())
    );
}

#[test]
fn an_empty_request_id_is_refused() {
    let mut anonymous = request(vec![]);
    anonymous.request_id = String::new();
    assert_eq!(
        evaluate_inventory_url_redaction(&anonymous),
        Err("native_inventory_url_redaction_invalid".to_owned())
    );
}

#[test]
fn the_reply_binds_the_digest_of_the_request_it_answered() {
    let asked = request(vec![url("https://example.test/path")]);
    let other = request(vec![url("https://example.test/other")]);
    let decoded = reply(&asked);
    assert_eq!(decoded["request_id"], json!("req-1"));
    assert_eq!(decoded["status"], json!("ok"));
    assert_eq!(decoded["code"], json!("ok"));
    assert_ne!(decoded["request_sha256"], reply(&other)["request_sha256"]);
    let digest = decoded["request_sha256"].as_str().unwrap_or_default();
    assert!(digest.starts_with("sha256:"), "{digest}");
    assert_eq!(digest.len(), "sha256:".len() + 64);
}

#[test]
fn the_feature_the_transport_asks_for_is_the_one_the_contract_names() {
    assert_eq!(
        INVENTORY_URL_REDACTION_FEATURE,
        "inventory-url-redaction-v1"
    );
}
