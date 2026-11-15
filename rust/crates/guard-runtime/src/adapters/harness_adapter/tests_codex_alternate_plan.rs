//! `alternate_plan`: the install plan for a Codex config besides the main one.

use base64::Engine as _;
use serde_json::{json, Value};

use super::Home;

fn encoded(text: &str) -> Value {
    json!(base64::engine::general_purpose::STANDARD.encode(text))
}

fn fields(home: &Home, before_config: Option<&str>) -> Value {
    let dir = home.home().join("project/.codex");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), "model = \"o3\"\n").unwrap();
    json!({
        "config": dir.join("config.toml"),
        "hooks": dir.join("hooks.json"),
        "before_config": before_config.map_or(Value::Null, encoded),
        "before_hooks": null,
        "managed_server_names": [],
        "require_owners": false,
        "cwd": null,
        "guard_home": home.guard(),
        "package_root": "/opt/guard/site",
        "expected": "[]",
        "argv": ["/g/hol-guard-runtime", "codex-hook-bridge", "{}"],
        "legacy_argv": ["/py", "-m", "codex_plugin_scanner.cli"],
        "statuses": [],
        "windows": false,
        "long_paths": {},
    })
}

#[test]
fn a_config_changed_since_the_read_is_a_conflict() {
    let home = Home::new();
    let answer = home.ask(
        "codex",
        "alternate_plan",
        fields(&home, Some("model = \"o1\"\n")),
    );
    assert_eq!(answer, json!({"conflict": true}));
}

#[test]
fn a_config_without_guard_entries_stays_as_it_is() {
    let home = Home::new();
    let answer = home.ask(
        "codex",
        "alternate_plan",
        fields(&home, Some("model = \"o3\"\n")),
    );
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 2, "{answer}");
    assert_eq!(files[0]["before"], files[0]["after"], "{answer}");
}
