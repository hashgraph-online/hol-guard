use serde_json::{json, Map, Value};

use super::super::Failure;
use super::check_sources;

fn run(sources: Value) -> Result<Value, String> {
    let mut fields = Map::new();
    fields.insert("sources".into(), sources);
    check_sources(&fields).map_err(|failure| match failure {
        Failure::Runtime(message) => message,
        _ => "invalid".to_owned(),
    })
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
