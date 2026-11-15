//! `hook_migration`: the legacy `hooks.json` groups fold into the config,
//! `hooks.json` retires, and a changed config keeps its original.

use std::fs;

use serde_json::{json, Value};

use super::super::after;
use super::{group, Home};

fn fields(home: &Home, require_owners: bool) -> Value {
    let codex = home.home().join(".codex");
    json!({
        "config": codex.join("config.toml"),
        "hooks": codex.join("hooks.json"),
        "owned": "[]",
        "require_owners": require_owners,
        "cwd": null,
        "guard_home": home.guard(),
        "package_root": "/opt/guard/site",
        "expected": "[]",
        "argv": ["/g/hol-guard-runtime", "codex-hook-bridge"],
        "legacy_argv": ["/py", "-m", "codex_plugin_scanner.cli"],
        "statuses": [],
        "windows": false,
        "long_paths": {},
    })
}

fn write(home: &Home, name: &str, text: &str) {
    let codex = home.home().join(".codex");
    fs::create_dir_all(&codex).unwrap();
    fs::write(codex.join(name), text).unwrap();
}

#[test]
fn legacy_groups_fold_into_the_config_and_the_original_is_kept() {
    let home = Home::new();
    write(
        &home,
        "config.toml",
        "# mine\nmodel = \"o3\"\nwhen = 1979-05-27\n",
    );
    let hooks = json!({"hooks": {"Stop": [group("echo done", 5)]}});
    write(&home, "hooks.json", &hooks.to_string());
    let answer = home.ask("codex", "hook_migration", fields(&home, false));
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    let rendered = after(&files[0]);
    assert!(rendered.starts_with("# mine\nmodel = \"o3\"\nwhen = 1979-05-27\n"));
    assert!(rendered.contains("echo done"));
    assert_eq!(files[0]["after_mode"], 0o600);
    assert_eq!(files[1]["after"], Value::Null);
    assert!(files[2]["path"]
        .as_str()
        .unwrap()
        .contains("migration-backups"));
    let config: Value = serde_json::from_str(answer["config"].as_str().unwrap()).unwrap();
    let token = config["when"].as_str().unwrap();
    assert_eq!(
        answer["tokens"][token],
        json!({"type": "date", "value": "1979-05-27"})
    );
}

#[test]
fn nothing_to_migrate_leaves_the_config_alone() {
    let home = Home::new();
    write(&home, "config.toml", "model = \"o3\"\n");
    let answer = home.ask("codex", "hook_migration", fields(&home, true));
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["before"], files[0]["after"]);
    assert_eq!(files[1]["before"], Value::Null);
}

#[test]
fn unreadable_sources_are_refused_with_the_inventory_reason() {
    let home = Home::new();
    write(&home, "config.toml", "a = 1\na = 2\n");
    let answer = home.ask("codex", "hook_migration", fields(&home, false));
    let error = answer["runtime_error"].as_str().unwrap();
    assert!(error.starts_with("codex_hook_inventory_source_duplicate_key: "));

    let home = Home::new();
    write(&home, "hooks.json", r#"{"hooks": {}, "hooks": {}}"#);
    let answer = home.ask("codex", "hook_migration", fields(&home, false));
    let error = answer["runtime_error"].as_str().unwrap();
    assert!(error.contains("duplicate key 'hooks' in Codex hooks file"));

    let home = Home::new();
    write(&home, "hooks.json", "[]");
    let answer = home.ask("codex", "hook_migration", fields(&home, false));
    let error = answer["runtime_error"].as_str().unwrap();
    assert!(error.contains("non-object Codex hooks file"));
}
