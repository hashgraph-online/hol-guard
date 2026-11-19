use serde_json::{json, Value};

use super::super::{Failure, Step};
use super::{check, check_sources};

fn outcome(result: Step<Value>) -> Result<Value, String> {
    result.map_err(|failure| match failure {
        Failure::Runtime(message) => message,
        _ => "invalid".to_owned(),
    })
}

fn run(sources: Value) -> Result<Value, String> {
    let Value::Array(sources) = sources else {
        panic!("sources are an array");
    };
    outcome(check(&sources))
}

fn run_pairs(fields: Value) -> Result<Value, String> {
    let Value::Object(fields) = fields else {
        panic!("fields are an object");
    };
    outcome(check_sources(&fields))
}

fn encoded(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[test]
fn absent_and_valid_sources_pass() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "model = \"x\"\n").unwrap();
    let hooks = dir.path().join("hooks.json");
    let missing = dir.path().join("missing.json");
    let sources = json!([
        {"path": config, "label": "Codex config file", "kind": "toml"},
        {"path": missing, "label": "Codex hooks file", "kind": "json"},
        {"path": hooks, "label": "Codex hooks file", "kind": "json", "data": null},
        {"path": hooks, "label": "Codex hooks file", "kind": "json", "data": encoded(b"{}")},
    ]);
    assert_eq!(run(sources), Ok(json!({"checked": 4})));
}

#[test]
fn a_captured_duplicate_key_refuses_with_its_label() {
    let sources = json!([{
        "path": "/h/hooks.json", "label": "Codex hooks file", "kind": "json",
        "data": encoded(b"{\"a\": 1, \"a\": 2}"),
    }]);
    let message = run(sources).unwrap_err();
    assert!(
        message.starts_with("codex_hook_inventory_source_duplicate_key: "),
        "{message}"
    );
    assert!(message.contains("duplicate key 'a' in Codex hooks file at /h/hooks.json"));
}

#[test]
fn malformed_toml_and_non_object_json_refuse() {
    let toml = json!([{
        "path": "/h/config.toml", "label": "Codex config file", "kind": "toml",
        "data": encoded(b"a = "),
    }]);
    assert!(run(toml)
        .unwrap_err()
        .starts_with("codex_hook_inventory_source_malformed: "));
    let json = json!([{
        "path": "/h/hooks.json", "label": "Codex hooks file", "kind": "json",
        "data": encoded(b"[]"),
    }]);
    assert!(run(json)
        .unwrap_err()
        .contains("non-object Codex hooks file"));
}

#[test]
fn a_directory_source_refuses_as_non_file() {
    let dir = tempfile::tempdir().unwrap();
    let sources = json!([{"path": dir.path(), "label": "Codex config file", "kind": "toml"}]);
    let message = run(sources).unwrap_err();
    assert!(message.starts_with("codex_hook_inventory_source_unreadable: Guard refused to overwrite non-file Codex config file"));
}

#[cfg(unix)]
#[test]
fn a_linked_source_refuses_as_non_file() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.json");
    std::fs::write(&target, "{}").unwrap();
    let link = dir.path().join("hooks.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let sources = json!([{"path": link, "label": "Codex hooks file", "kind": "json"}]);
    assert!(run(sources)
        .unwrap_err()
        .contains("non-file Codex hooks file"));
}

#[test]
fn an_unknown_kind_is_invalid() {
    let sources = json!([{"path": "/x", "label": "l", "kind": "yaml", "data": null}]);
    assert_eq!(run(sources), Err("invalid".to_owned()));
}

#[test]
fn pairs_read_each_file_from_disk_with_its_label() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "model = \"x\"\n").unwrap();
    let hooks = dir.path().join("hooks.json");
    std::fs::write(&hooks, "{\"a\": 1, \"a\": 2}").unwrap();
    let message = run_pairs(json!({"pairs": [[config, hooks]]})).unwrap_err();
    assert!(
        message.contains("duplicate key 'a' in Codex hooks file at"),
        "{message}"
    );
    std::fs::write(&hooks, "{}").unwrap();
    assert_eq!(
        run_pairs(json!({"pairs": [[config, hooks]]})),
        Ok(json!({"checked": 2}))
    );
}

#[test]
fn pairs_check_captured_bytes_not_the_disk() {
    let pairs = json!([["/h/config.toml", "/h/hooks.json"]]);
    let captured = json!({
        "/h/config.toml": encoded(b"model = \"x\"\n"),
        "/h/hooks.json": null,
    });
    assert_eq!(
        run_pairs(json!({"pairs": pairs, "contents": captured})),
        Ok(json!({"checked": 2}))
    );
    let malformed = json!({"/h/config.toml": encoded(b"a = "), "/h/hooks.json": null});
    let message = run_pairs(json!({"pairs": pairs, "contents": malformed})).unwrap_err();
    assert!(
        message.starts_with("codex_hook_inventory_source_malformed: "),
        "{message}"
    );
    assert!(
        message.contains("Codex config file at /h/config.toml"),
        "{message}"
    );
}

#[test]
fn malformed_pair_requests_are_invalid() {
    for fields in [
        json!({}),
        json!({"pairs": [["/h/config.toml"]]}),
        json!({"pairs": [["/h/config.toml", 3]]}),
        json!({"pairs": [["/h/config.toml", "/h/hooks.json"]], "contents": []}),
        json!({"pairs": [["/h/config.toml", "/h/hooks.json"]], "contents": {"/h/config.toml": null}}),
    ] {
        assert_eq!(run_pairs(fields), Err("invalid".to_owned()));
    }
}
