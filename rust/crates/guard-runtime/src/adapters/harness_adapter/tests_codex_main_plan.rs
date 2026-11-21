//! `main_plan`: the main Codex config's part of an install plan.

use base64::Engine as _;
use serde_json::{json, Value};

use super::Home;

fn encoded(text: &str) -> Value {
    json!(base64::engine::general_purpose::STANDARD.encode(text))
}

fn fields(home: &Home, before_config: &str) -> Value {
    let dir = home.home().join(".codex");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.toml"), "model = \"o3\"\n").unwrap();
    json!({
        "config": dir.join("config.toml"),
        "hooks": dir.join("hooks.json"),
        "before_config": encoded(before_config),
        "before_hooks": null,
        "owned": "[]",
        "managed": "{}",
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
    let answer = home.ask("codex", "main_plan", fields(&home, "model = \"o1\"\n"));
    assert_eq!(answer, json!({"conflict": true}));
}

#[test]
fn the_backup_captures_the_config_the_install_replaces() {
    let home = Home::new();
    let answer = home.ask("codex", "main_plan", fields(&home, "model = \"o3\"\n"));
    assert_eq!(
        answer["backup"]["after"],
        encoded("model = \"o3\"\n"),
        "{answer}"
    );
    assert!(
        answer["config"].as_str().unwrap().contains("\"model\""),
        "{answer}"
    );
    assert_eq!(answer["files"].as_array().unwrap().len(), 1, "{answer}");
}
