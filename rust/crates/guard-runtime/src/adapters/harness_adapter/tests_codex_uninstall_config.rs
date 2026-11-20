//! `uninstall_config`: the main Codex config an uninstall writes.

use base64::Engine as _;
use serde_json::{json, Value};

use super::Home;

fn encoded(text: &str) -> Value {
    json!(base64::engine::general_purpose::STANDARD.encode(text))
}

fn fields(home: &Home, current: &str, original: Option<&str>) -> Value {
    json!({
        "config": home.home().join(".codex/config.toml"),
        "hooks_json": home.home().join(".codex/hooks.json"),
        "current": encoded(current),
        "original": original.map_or(Value::Null, encoded),
        "owned": "[]",
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
fn an_unchanged_config_returns_the_backup_bytes() {
    let home = Home::new();
    let original = "# mine\nmodel = \"o3\"\n";
    let current = "model = \"o3\"\n\n[features]\nhooks = true\n";
    let answer = home.ask(
        "codex",
        "uninstall_config",
        fields(&home, current, Some(original)),
    );
    assert_eq!(answer, json!({"delete": false, "text": original}));
}

#[test]
fn a_later_setting_survives_and_the_hook_feature_goes() {
    let home = Home::new();
    let original = "model = \"o3\"\n";
    let current = "model = \"o3\"\napproval_policy = \"never\"\n\n[features]\nhooks = true\n";
    let answer = home.ask(
        "codex",
        "uninstall_config",
        fields(&home, current, Some(original)),
    );
    assert_eq!(answer["delete"], false);
    let text = answer["text"].as_str().unwrap();
    assert!(text.contains("approval_policy = \"never\""), "{text}");
    assert!(!text.contains("hooks"), "{text}");
}

#[test]
fn without_a_backup_or_bindings_the_config_stays() {
    let home = Home::new();
    let current = "[[hooks.Stop]]\nmatcher = \"*\"\n";
    let answer = home.ask("codex", "uninstall_config", fields(&home, current, None));
    assert_eq!(answer, json!({"delete": false, "text": null}));
}

#[test]
fn an_unreadable_backup_is_refused_by_name() {
    let home = Home::new();
    let answer = home.ask(
        "codex",
        "uninstall_config",
        fields(&home, "model = \"o3\"\n", Some("[hooks\n")),
    );
    let error = answer["runtime_error"].as_str().unwrap();
    assert!(error.contains("Codex config backup"), "{error}");
}

#[test]
fn a_config_the_install_created_is_deleted() {
    let home = Home::new();
    let current = "[features]\nhooks = true\n";
    let answer = home.ask(
        "codex",
        "uninstall_config",
        fields(&home, current, Some("")),
    );
    assert_eq!(answer, json!({"delete": true, "text": null}));
}
