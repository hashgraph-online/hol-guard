use std::fs;
use std::path::Path;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use super::answer;

const MACHINE: &str = "11111111111111111111111111111111";
const GENERATION: &str = "22222222222222222222222222222222";
const FINGERPRINT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn micros(text: &str) -> i64 {
    crate::policy_bundle_time::from_isoformat(text)
        .and_then(|parsed| parsed.utc_micros())
        .expect("timestamp")
}

fn now() -> i64 {
    micros("2026-10-31T12:00:00+00:00")
}

fn run(mut request: Value, now: i64) -> Result<Value, (String, String)> {
    request["schema"] = json!("removal-evidence.v1");
    let bytes = serde_json::to_vec(&request).expect("request");
    match answer(&bytes, now).expect("request is well formed") {
        Ok(fields) => Ok(Value::Object(fields)),
        Err((kind, code)) => Err((kind.to_owned(), code.to_owned())),
    }
}

fn refused(request: Value, now: i64) -> (String, String) {
    run(request, now).expect_err("refused")
}

fn value_refusal(code: &str) -> (String, String) {
    ("value".to_owned(), code.to_owned())
}

fn issue_request(root: &Path, name: Option<&str>) -> Value {
    json!({
        "op": "issue",
        "root": root,
        "name": name,
        "home": "/home/developer",
        "user": "developer",
        "actor": "mdm-admin@example.test",
        "reason": "approved device retirement",
        "machine_installation_id": MACHINE,
        "installation_generation": GENERATION,
    })
}

fn authorization(overrides: &[(&str, Value)]) -> Value {
    let mut payload = json!({
        "actor": "mdm-admin@example.test",
        "expiresAt": "2026-10-31T12:01:00+00:00",
        "home": "/home/developer",
        "installationGeneration": GENERATION,
        "issuedAt": "2026-10-31T11:59:00+00:00",
        "machineInstallationId": MACHINE,
        "nonce": "unique-removal-nonce",
        "operation": "deactivate",
        "reason": "approved device retirement",
        "user": "developer",
    });
    for (key, value) in overrides {
        if value.is_null() {
            payload.as_object_mut().expect("object").remove(*key);
        } else {
            payload[*key] = value.clone();
        }
    }
    payload
}

fn check_request(content: &[u8]) -> Value {
    json!({
        "op": "check",
        "content": STANDARD.encode(content),
        "home": "/home/developer",
        "user": "developer",
    })
}

fn check_payload(payload: &Value) -> Result<Value, (String, String)> {
    run(check_request(payload.to_string().as_bytes()), now())
}

fn tombstone_request(root: &Path, status: &str) -> Value {
    json!({
        "op": "tombstone",
        "root": root,
        "status": status,
        "evidence": {
            "fingerprint": FINGERPRINT,
            "actor": "mdm-admin@example.test",
            "reason": "retire \u{e9}",
            "machine_installation_id": MACHINE,
            "installation_generation": GENERATION,
            "issued_at": "2026-10-31T12:00:00+00:00",
            "expires_at": "2026-10-31T12:02:00+00:00",
        },
    })
}

#[test]
fn an_issued_authorization_is_private_and_checks_back() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-authorizations");
    let issued = run(issue_request(&root, Some("developer.json")), now()).expect("issued");
    let target = root.join("developer.json");
    assert_eq!(issued["path"], json!(target.to_str().expect("utf-8")));
    assert_eq!(issued["issued_at"], json!("2026-10-31T12:00:00+00:00"));
    assert_eq!(issued["expires_at"], json!("2026-10-31T12:02:00+00:00"));
    let bytes = fs::read(&target).expect("authorization");
    assert!(bytes.ends_with(b"}\n"));
    assert!(bytes.starts_with(b"{\"actor\": \"mdm-admin@example.test\", \"expiresAt\": "));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode(&target), 0o600);
        assert_eq!(mode(&root), 0o700);
    }
    let checked = run(check_request(&bytes), micros("2026-10-31T12:01:00+00:00")).expect("valid");
    assert_eq!(checked["fingerprint"], issued["fingerprint"]);
    assert_eq!(checked["installation_generation"], json!(GENERATION));
    assert_eq!(checked["issued_at"], issued["issued_at"]);
    let nonce = serde_json::from_slice::<Value>(&bytes).expect("json")["nonce"].clone();
    assert_eq!(nonce.as_str().map(str::len), Some(32));
}

#[test]
fn an_issued_authorization_is_never_overwritten_or_misnamed() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-authorizations");
    run(issue_request(&root, Some("developer.json")), now()).expect("issued");
    assert_eq!(
        refused(issue_request(&root, Some("developer.json")), now()),
        (
            "os".to_owned(),
            "mdm_removal_authorization_exists".to_owned()
        )
    );
    let long = format!("{}.json", "a".repeat(129));
    for name in [
        "../escape.json",
        "developer.txt",
        ".json",
        "dev eloper.json",
        long.as_str(),
    ] {
        assert_eq!(
            refused(issue_request(&root, Some(name)), now()),
            value_refusal("mdm_removal_authorization_name_invalid"),
            "{name}"
        );
    }
    let edge = format!("{}.json", "a".repeat(128));
    run(issue_request(&root, Some(&edge)), now()).expect("128-byte stem");
    let issued = run(issue_request(&root, None), now()).expect("default name");
    let name = Path::new(issued["path"].as_str().expect("path"))
        .file_name()
        .and_then(|name| name.to_str())
        .expect("name")
        .to_owned();
    let random = name
        .strip_prefix("developer-")
        .and_then(|rest| rest.strip_suffix(".json"))
        .expect("default spelling");
    assert_eq!(random.len(), 16);
    assert!(random.bytes().all(|byte| byte.is_ascii_hexdigit()));
}

#[test]
fn an_authorization_names_a_plain_actor_and_a_printable_reason() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-authorizations");
    let with = |key: &str, value: Value| {
        let mut request = issue_request(&root, Some("developer.json"));
        request[key] = value;
        refused(request, now())
    };
    let long_actor = format!("a{}", "b".repeat(128));
    for actor in [
        "",
        "-admin",
        "admin user",
        "admin\n",
        "\u{e9}admin",
        long_actor.as_str(),
    ] {
        assert_eq!(
            with("actor", json!(actor)),
            value_refusal("mdm_removal_authorization_actor_invalid"),
            "{actor:?}"
        );
    }
    for reason in [String::new(), "line\nbreak".to_owned(), "x".repeat(257)] {
        assert_eq!(
            with("reason", json!(reason)),
            value_refusal("mdm_removal_authorization_reason_invalid")
        );
    }
    assert_eq!(
        with("installation_generation", json!("2".repeat(31))),
        value_refusal("mdm_removal_authorization_invalid")
    );
    assert!(!root.join("developer.json").exists());
    let mut request = issue_request(&root, Some("developer.json"));
    request["reason"] = json!("\u{e9}".repeat(256));
    run(request, now()).expect("256 characters, not bytes");
}

#[test]
fn a_checked_authorization_must_hold_exactly_its_fields() {
    check_payload(&authorization(&[])).expect("valid");
    let invalid = value_refusal("mdm_removal_authorization_invalid");
    let wrong_scope = value_refusal("mdm_removal_authorization_wrong_scope");
    for (key, value) in [
        ("nonce", Value::Null),
        ("extra", json!("x")),
        ("nonce", json!("")),
        ("nonce", json!(7)),
        ("actor", json!("")),
        ("machineInstallationId", json!("A".repeat(32))),
        ("installationGeneration", json!("2".repeat(33))),
    ] {
        assert_eq!(
            check_payload(&authorization(&[(key, value)])),
            Err(invalid.clone()),
            "{key}"
        );
    }
    for (key, value) in [
        ("operation", json!("activate")),
        ("user", json!("someone")),
        ("user", json!(1)),
        ("home", json!("/home/developer/")),
    ] {
        assert_eq!(
            check_payload(&authorization(&[(key, value)])),
            Err(wrong_scope.clone()),
            "{key}"
        );
    }
    assert_eq!(
        check_payload(&authorization(&[("actor", json!("bad actor"))])),
        Err(value_refusal("mdm_removal_authorization_actor_invalid"))
    );
    assert_eq!(
        check_payload(&authorization(&[("reason", json!("tab\there"))])),
        Err(value_refusal("mdm_removal_authorization_reason_invalid"))
    );
    for content in [
        &b"[]"[..],
        &b"{"[..],
        &b"\xff{}"[..],
        &b"\xef\xbb\xbf{}"[..],
    ] {
        assert_eq!(run(check_request(content), now()), Err(invalid.clone()));
    }
    let oversized = format!("{{\"pad\": \"{}\"}}", "x".repeat(16 * 1024));
    assert_eq!(
        run(check_request(oversized.as_bytes()), now()),
        Err(invalid.clone())
    );
    let mut request = check_request(b"{}");
    request["content"] = json!("not base64!");
    assert_eq!(run(request, now()), Err(invalid));
}

#[test]
fn a_checked_authorization_is_short_lived() {
    let expired = Err(value_refusal("mdm_removal_authorization_expired"));
    let at = |issued: &str, expires: &str| {
        check_payload(&authorization(&[
            ("issuedAt", json!(issued)),
            ("expiresAt", json!(expires)),
        ]))
    };
    at(
        "2026-10-31T11:55:00.000001+00:00",
        "2026-10-31T12:00:00.000001+00:00",
    )
    .expect("five minutes");
    at("2026-10-31T12:00:00Z", "2026-10-31T13:00:00+01:00").expect_err("expires at now");
    at("2026-10-31T13:00:00+01:00", "2026-10-31T12:01:00Z").expect("offsets compare as instants");
    for (issued, expires) in [
        ("2026-10-31T11:59:00", "2026-10-31T12:01:00+00:00"),
        ("2026-10-31T11:59:00+00:00", "2026-10-31T12:01:00"),
        (
            "2026-10-31T12:00:00.000001+00:00",
            "2026-10-31T12:01:00+00:00",
        ),
        ("2026-10-31T11:58:00+00:00", "2026-10-31T12:00:00+00:00"),
        (
            "2026-10-31T11:54:59.999999+00:00",
            "2026-10-31T12:01:00+00:00",
        ),
        (
            "2026-10-31T11:59:00+00:00",
            "2026-10-31T12:04:00.000001+00:00",
        ),
    ] {
        assert_eq!(at(issued, expires), expired, "{issued} {expires}");
    }
    assert_eq!(
        at("yesterday", "2026-10-31T12:01:00+00:00"),
        Err(value_refusal("mdm_removal_authorization_invalid"))
    );
}

#[test]
fn a_tombstone_records_each_allowed_step_in_python_spelling() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-tombstones");
    let recorded = run(tombstone_request(&root, "started"), now()).expect("started");
    let target = root.join(format!("{FINGERPRINT}.json"));
    assert_eq!(recorded["path"], json!(target.to_str().expect("utf-8")));
    let expected = concat!(
        "{\"actor\": \"mdm-admin@example.test\", \"authorizationExpiresAt\": \"2026-10-31T12:02:00+00:00\", ",
        "\"authorizationFingerprint\": \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", ",
        "\"authorizationIssuedAt\": \"2026-10-31T12:00:00+00:00\", ",
        "\"events\": [{\"at\": \"2026-10-31T12:00:00+00:00\", \"status\": \"started\"}], ",
        "\"installationGeneration\": \"22222222222222222222222222222222\", ",
        "\"machineInstallationId\": \"11111111111111111111111111111111\", \"operation\": \"deactivate\", ",
        "\"reason\": \"retire \\u00e9\", \"schemaVersion\": \"hol-guard-removal-tombstone.v1\", ",
        "\"status\": \"started\", \"updatedAt\": \"2026-10-31T12:00:00+00:00\"}\n",
    );
    assert_eq!(fs::read_to_string(&target).expect("tombstone"), expected);
    run(
        tombstone_request(&root, "completed"),
        micros("2026-10-31T12:00:00.25+00:00"),
    )
    .expect("completed");
    let completed: Value =
        serde_json::from_slice(&fs::read(&target).expect("tombstone")).expect("json");
    assert_eq!(completed["status"], json!("completed"));
    assert_eq!(
        completed["updatedAt"],
        json!("2026-10-31T12:00:00.250000+00:00")
    );
    assert_eq!(completed["events"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        refused(tombstone_request(&root, "failed"), now()),
        value_refusal("mdm_removal_tombstone_transition_invalid")
    );
    assert_eq!(
        refused(tombstone_request(&root, "removed"), now()),
        value_refusal("mdm_removal_tombstone_status_invalid")
    );
    let names: Vec<_> = fs::read_dir(&root)
        .expect("root")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert_eq!(names.len(), 1, "no temporary file is left behind");
}

#[test]
fn a_tombstone_starts_only_from_issue_or_start() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-tombstones");
    for status in ["completed", "failed"] {
        assert_eq!(
            refused(tombstone_request(&root, status), now()),
            value_refusal("mdm_removal_tombstone_transition_invalid")
        );
    }
    run(tombstone_request(&root, "issued"), now()).expect("issued");
    assert_eq!(
        refused(tombstone_request(&root, "issued"), now()),
        value_refusal("mdm_removal_tombstone_transition_invalid")
    );
    run(tombstone_request(&root, "started"), now()).expect("started");
    run(tombstone_request(&root, "failed"), now()).expect("failed");
}

#[test]
fn a_tombstone_that_does_not_match_its_history_is_refused() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-tombstones");
    let target = root.join(format!("{FINGERPRINT}.json"));
    run(tombstone_request(&root, "issued"), now()).expect("issued");
    let original: Value =
        serde_json::from_slice(&fs::read(&target).expect("tombstone")).expect("json");
    let tampered = |change: &dyn Fn(&mut Value)| {
        let mut stored = original.clone();
        change(&mut stored);
        fs::write(&target, stored.to_string()).expect("write");
        refused(tombstone_request(&root, "started"), now())
    };
    let invalid = value_refusal("mdm_removal_tombstone_invalid");
    assert_eq!(
        tampered(&|stored: &mut Value| stored["actor"] = json!("someone-else")),
        value_refusal("mdm_removal_tombstone_identity_mismatch")
    );
    let cases: [&dyn Fn(&mut Value); 9] = [
        &|stored: &mut Value| stored["status"] = json!("started"),
        &|stored: &mut Value| stored["updatedAt"] = json!("2026-10-31T12:00:01+00:00"),
        &|stored: &mut Value| stored["extra"] = json!(true),
        &|stored: &mut Value| stored["events"] = json!([]),
        &|stored: &mut Value| stored["events"][0]["status"] = json!("completed"),
        &|stored: &mut Value| stored["events"][0]["at"] = json!("2026-10-31T12:00:00"),
        &|stored: &mut Value| stored["events"][0]["extra"] = json!(1),
        &|stored: &mut Value| {
            stored["events"] = json!([
                {"at": "2026-10-31T12:00:00+00:00", "status": "issued"},
                {"at": "2026-10-31T11:59:59+00:00", "status": "started"},
            ]);
            stored["status"] = json!("started");
            stored["updatedAt"] = json!("2026-10-31T11:59:59+00:00");
        },
        &|stored: &mut Value| *stored = json!([]),
    ];
    for (index, change) in cases.iter().enumerate() {
        assert_eq!(tampered(*change), invalid, "case {index}");
    }
    fs::write(&target, b"not json").expect("write");
    assert_eq!(refused(tombstone_request(&root, "started"), now()), invalid);
    let same_instant = json!([
        {"at": "2026-10-31T12:00:00+00:00", "status": "issued"},
        {"at": "2026-10-31T13:00:00+01:00", "status": "started"},
    ]);
    let mut stored = original.clone();
    stored["events"] = same_instant;
    stored["status"] = json!("started");
    stored["updatedAt"] = json!("2026-10-31T13:00:00+01:00");
    fs::write(&target, stored.to_string()).expect("write");
    run(tombstone_request(&root, "completed"), now()).expect("equal instants keep order");
}

#[cfg(unix)]
#[test]
fn a_linked_tombstone_is_never_read() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-tombstones");
    fs::create_dir(&root).expect("root");
    let elsewhere = directory.path().join("elsewhere.json");
    fs::write(&elsewhere, b"{}").expect("write");
    std::os::unix::fs::symlink(&elsewhere, root.join(format!("{FINGERPRINT}.json"))).expect("link");
    assert_eq!(
        refused(tombstone_request(&root, "started"), now()),
        value_refusal("mdm_removal_tombstone_invalid")
    );
}

#[test]
fn a_full_tombstone_store_refuses_a_new_removal() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("removal-tombstones");
    fs::create_dir(&root).expect("root");
    for index in 0..4096 {
        fs::write(root.join(format!("{index}.json")), b"").expect("write");
    }
    assert_eq!(
        refused(tombstone_request(&root, "started"), now()),
        (
            "os".to_owned(),
            "mdm_removal_tombstone_capacity_exceeded".to_owned()
        )
    );
    let mut request = tombstone_request(&root, "started");
    request["evidence"]["fingerprint"] = json!("A".repeat(64));
    assert_eq!(
        refused(request, now()),
        value_refusal("mdm_removal_tombstone_invalid")
    );
}

#[test]
fn a_malformed_request_fails_the_command() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut unknown = tombstone_request(directory.path(), "started");
    unknown["extra"] = json!(1);
    let mut wrong_schema = tombstone_request(directory.path(), "started");
    wrong_schema["schema"] = json!("removal-evidence.v0");
    let wrong_op = json!({"schema": "removal-evidence.v1", "op": "delete"});
    let mut unschema = unknown.clone();
    unschema["schema"] = json!("removal-evidence.v1");
    for request in [unschema, wrong_schema, wrong_op] {
        let bytes = serde_json::to_vec(&request).expect("request");
        assert!(answer(&bytes, now()).is_err(), "{request}");
    }
    assert!(answer(b"[]", now()).is_err());
    let response = super::run_command(&b"{}"[..]);
    assert_eq!(response, Err("removal_evidence_request_invalid".to_owned()));
}
