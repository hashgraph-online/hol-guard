use std::fs;

use super::*;

fn run(request: Value) -> Result<Value, String> {
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn text(path: &Path, extra: Value) -> Value {
    let mut request = json!({ "schema": SCHEMA, "op": "text", "path": path });
    for (key, value) in extra.as_object().expect("object") {
        request[key] = value.clone();
    }
    run(request).expect("text answer")["file"].clone()
}

fn config(path: &Path, syntax: &str) -> (Value, String) {
    let request = json!({ "schema": SCHEMA, "op": "config", "path": path, "syntax": syntax });
    let bytes = run_command(request.to_string().as_bytes()).expect("config answer");
    let text = String::from_utf8(bytes).expect("utf-8");
    (serde_json::from_str(&text).expect("JSON"), text)
}

#[test]
fn text_keeps_the_complete_content_under_the_limit() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("allow.json");
    fs::write(&path, "{\"approvals\": []}").expect("write");

    let file = text(&path, json!({ "content_limit_bytes": 1024 }));

    assert_eq!(file["complete"], json!(true));
    assert_eq!(file["readable"], json!(true));
    assert_eq!(file["content"], json!("{\"approvals\": []}"));
    assert_eq!(file["size_bytes"], json!(17));
    assert!(file["content_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert_eq!(file["reason"], Value::Null);
}

#[test]
fn text_without_a_limit_hashes_but_keeps_no_content() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("SKILL.md");
    fs::write(&path, "x".repeat(70_000)).expect("write");

    let file = text(&path, json!({}));

    assert_eq!(file["complete"], json!(true));
    assert_eq!(file["content"], Value::Null);
    assert_eq!(file["analysis_truncated"], json!(true));
    assert_eq!(file["preview"].as_str().map(str::len), Some(64 * 1024));
}

#[test]
fn oversized_text_is_hashed_but_incomplete() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("allow.json");
    fs::write(&path, "12345").expect("write");

    let file = text(&path, json!({ "content_limit_bytes": 4 }));

    assert_eq!(file["complete"], json!(false));
    assert_eq!(file["readable"], json!(true));
    assert_eq!(file["content"], Value::Null);
    assert!(file["content_hash"].is_string());
    assert_eq!(file["reason"], json!("file_too_large"));
}

#[test]
fn missing_and_non_regular_files_are_typed() {
    let directory = tempfile::tempdir().expect("tempdir");

    let missing = text(&directory.path().join("absent"), json!({}));
    let directory_file = text(directory.path(), json!({}));

    assert_eq!(missing["reason"], json!("file_missing"));
    assert_eq!(missing["readable"], json!(false));
    assert_eq!(directory_file["reason"], json!("file_not_regular"));
}

#[cfg(unix)]
#[test]
fn links_and_scope_escapes_are_refused() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().expect("tempdir");
    let scope = directory.path().join("scope");
    fs::create_dir_all(&scope).expect("scope");
    let outside = directory.path().join("outside.json");
    fs::write(&outside, "{}").expect("outside");
    let link = scope.join("link.json");
    symlink(&outside, &link).expect("link");
    let linked_scope = directory.path().join("linked-scope");
    symlink(directory.path(), &linked_scope).expect("linked scope");

    assert_eq!(
        text(&link, json!({}))["reason"],
        json!("file_symlink_unsupported")
    );
    assert_eq!(
        text(&outside, json!({ "scope_root": scope }))["reason"],
        json!("file_symlink_escape")
    );
    assert_eq!(
        text(
            &linked_scope.join("outside.json"),
            json!({ "scope_root": scope })
        )["reason"],
        json!("file_symlink_escape")
    );
}

#[test]
fn yaml_config_keeps_key_order_and_exact_values() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("config.yaml");
    fs::write(
        &path,
        "zeta: 1\nalpha:\n  big: 123456789012345678901234567890\n  mode: 0755\n  enabled: yes\n  ratio: 1.5\nmcp_servers: {}\n",
    )
    .expect("write");

    let (answer, raw) = config(&path, "yaml");

    assert_eq!(answer["complete"], json!(true));
    assert_eq!(answer["reason"], Value::Null);
    assert_eq!(answer["file"]["content"], Value::Null);
    assert_eq!(answer["file"]["complete"], json!(true));
    assert!(raw.contains(
        "\"payload\":{\"zeta\":1,\"alpha\":{\"big\":123456789012345678901234567890,\"mode\":493,\"enabled\":true,\"ratio\":1.5},\"mcp_servers\":{}}"
    ));
}

#[test]
fn empty_yaml_is_an_empty_mapping_and_json_must_be_a_mapping() {
    let directory = tempfile::tempdir().expect("tempdir");
    let empty = directory.path().join("config.yaml");
    fs::write(&empty, "").expect("empty");
    let list = directory.path().join("mcp.json");
    fs::write(&list, "[1, 2]").expect("list");

    let (empty_answer, _) = config(&empty, "yaml");
    let (list_answer, _) = config(&list, "json");

    assert_eq!(empty_answer["payload"], json!({}));
    assert_eq!(empty_answer["complete"], json!(true));
    assert_eq!(list_answer["payload"], Value::Null);
    assert_eq!(list_answer["complete"], json!(false));
    assert_eq!(list_answer["reason"], json!("config_not_mapping"));
}

#[test]
fn config_failures_carry_the_loader_reason() {
    let directory = tempfile::tempdir().expect("tempdir");
    let cases = [
        ("dup.yaml", "yaml", "a: 1\na: 2\n", "config_duplicate_key"),
        (
            "alias.yaml",
            "yaml",
            "a: &x 1\nb: *x\n",
            "config_alias_limit_exceeded",
        ),
        (
            "dup.json",
            "json",
            "{\"a\": 1, \"a\": 2}",
            "config_duplicate_key",
        ),
        ("nan.json", "json", "{\"a\": NaN}", "config_value_invalid"),
        ("broken.yaml", "yaml", "a: [1, 2\n", "config_parse_error"),
    ];
    for (name, syntax, content, reason) in cases {
        let path = directory.path().join(name);
        fs::write(&path, content).expect("write");

        let (answer, _) = config(&path, syntax);

        assert_eq!(answer["complete"], json!(false), "{name}");
        assert_eq!(answer["payload"], Value::Null, "{name}");
        assert_eq!(answer["reason"], json!(reason), "{name}");
    }
}

#[test]
fn a_value_the_loader_cannot_construct_is_a_parse_error() {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("config.yaml");
    fs::write(&path, "flag: !!bool maybe\n").expect("write");

    let (answer, _) = config(&path, "yaml");

    assert_eq!(answer["complete"], json!(false));
    assert_eq!(answer["payload"], Value::Null);
    assert_eq!(answer["reason"], json!("config_parse_error"));
    assert_eq!(answer["file"]["complete"], json!(true));
}

#[test]
fn an_unreadable_config_reports_the_file_reason() {
    let directory = tempfile::tempdir().expect("tempdir");

    let (answer, _) = config(&directory.path().join("absent.yaml"), "yaml");

    assert_eq!(answer["complete"], json!(false));
    assert_eq!(answer["reason"], json!("file_missing"));
    assert_eq!(answer["file"]["reason"], json!("file_missing"));
}

#[test]
fn ordered_json_has_no_form_for_a_non_finite_float() {
    assert_eq!(ordered_json(&PyVal::Float(f64::INFINITY)), None);
    assert_eq!(
        ordered_json(&PyVal::List(vec![
            PyVal::Float(1e20),
            PyVal::Str("q\"\n".to_owned())
        ])),
        Some("[1e+20,\"q\\\"\\n\"]".to_owned())
    );
}

#[test]
fn requests_are_validated() {
    let absolute = std::env::temp_dir().join("hermes.yaml");
    let refused = [
        json!({ "schema": "hermes-file-inspect.v0", "op": "text", "path": absolute }),
        json!({ "schema": SCHEMA, "op": "text", "path": "relative.yaml" }),
        json!({ "schema": SCHEMA, "op": "text", "path": absolute, "scope_root": "relative" }),
        json!({ "schema": SCHEMA, "op": "text", "path": absolute, "syntax": "yaml" }),
        json!({ "schema": SCHEMA, "op": "text", "path": absolute, "content_limit_bytes": CONFIG_MAX_BYTES + 1 }),
        json!({ "schema": SCHEMA, "op": "config", "path": absolute }),
        json!({ "schema": SCHEMA, "op": "config", "path": absolute, "syntax": "toml" }),
        json!({ "schema": SCHEMA, "op": "config", "path": absolute, "syntax": "yaml", "content_limit_bytes": 1 }),
        json!({ "schema": SCHEMA, "op": "read", "path": absolute }),
        json!({ "schema": SCHEMA, "op": "text", "path": absolute, "extra": 1 }),
    ];
    for request in refused {
        assert!(run(request.clone()).is_err(), "{request}");
    }
}

#[cfg(unix)]
#[test]
fn a_file_without_read_permission_is_unreadable() {
    use std::os::unix::fs::PermissionsExt;

    if nix::unistd::geteuid().is_root() {
        return;
    }
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("SKILL.md");
    fs::write(&path, "content").expect("write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod");

    let file = text(&path, json!({}));

    assert_eq!(file["complete"], json!(false));
    assert_eq!(file["readable"], json!(false));
    assert_eq!(file["reason"], json!("file_unreadable"));
    assert_eq!(file["content_hash"], Value::Null);
}

#[cfg(target_os = "linux")]
#[test]
fn bytes_past_the_reported_size_are_a_change_during_read() {
    // procfs reports size 0 for a file that streams content, the same shape
    // as a file that grows while it is hashed.
    let file = text(Path::new("/proc/self/status"), json!({}));

    assert_eq!(file["complete"], json!(false));
    assert_eq!(file["reason"], json!("file_changed_during_read"));
    assert_eq!(file["content_hash"], Value::Null);
}
