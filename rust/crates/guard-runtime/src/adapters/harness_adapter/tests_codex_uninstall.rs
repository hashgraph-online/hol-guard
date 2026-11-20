//! `uninstall_restore`: uninstall reverses what install changed in the Codex
//! config and keeps every setting the user changed after install.

use serde_json::{json, Value};

use super::{group, Home, PROXY_ARGS};

fn restore(payload: &Value, backup: Option<&Value>, hooks: Option<&Value>) -> Value {
    let home = Home::new();
    let mut fields = json!({"payload": payload.to_string()});
    fields["backup"] = backup.map_or(Value::Null, |backup| json!(backup.to_string()));
    if let Some(hooks) = hooks {
        fields["hooks"] = json!(hooks.to_string());
    }
    home.ask("codex", "uninstall_restore", fields)
}

fn rendered(answer: &Value) -> Value {
    serde_json::from_str(answer["rendered"].as_str().unwrap()).unwrap()
}

#[test]
fn settings_added_after_install_survive_uninstall() {
    let backup = json!({
        "model": "o3",
        "mcp_servers": {"docs": {"command": "npx", "args": ["docs-server"]}},
    });
    let installed = json!({
        "model": "gpt-5",
        "approval_policy": "on-request",
        "features": {"hooks": true},
        "hooks": {"PreToolUse": [group("guard", 30)]},
        "mcp_servers": {
            "docs": {"command": "/py", "args": PROXY_ARGS},
            "added": {"command": "uvx", "args": ["added-later"]},
        },
        "profiles": {"work": {"model": "o4-mini"}},
    });
    let answer = restore(&installed, Some(&backup), Some(&json!({})));
    assert_eq!(answer["changed"], true);
    assert_eq!(answer["delete"], false);
    assert_eq!(
        rendered(&answer),
        json!({
            "model": "gpt-5",
            "approval_policy": "on-request",
            "mcp_servers": {
                "docs": {"command": "npx", "args": ["docs-server"]},
                "added": {"command": "uvx", "args": ["added-later"]},
            },
            "profiles": {"work": {"model": "o4-mini"}},
        })
    );
}

#[test]
fn the_legacy_hook_feature_and_the_users_hooks_come_back() {
    let backup = json!({"features": {"codex_hooks": true, "web_search": true}});
    let installed = json!({
        "features": {"hooks": true, "web_search": true},
        "hooks": {"PreToolUse": [group("guard", 30), group("mine", 5)]},
    });
    let mine = json!({"PreToolUse": [group("mine", 5)]});
    let kept = rendered(&restore(&installed, Some(&backup), Some(&mine)));
    assert_eq!(kept["hooks"], mine);
    assert_eq!(kept["features"], json!({"hooks": true, "web_search": true}));

    let none = rendered(&restore(&installed, Some(&backup), Some(&json!({}))));
    assert_eq!(
        none,
        json!({"features": {"web_search": true, "codex_hooks": true}})
    );
}

#[test]
fn a_proxy_with_no_backup_entry_is_removed_and_a_new_file_is_deleted() {
    let installed = json!({
        "features": {"hooks": true},
        "hooks": {"PreToolUse": [group("guard", 30)]},
        "mcp_servers": {"p": {"command": "/py", "args": PROXY_ARGS}},
    });
    let answer = restore(&installed, None, Some(&json!({})));
    assert_eq!(rendered(&answer), json!({}));
    assert_eq!(answer["delete"], true);

    // A backup that parses empty, such as one holding only comments, is a
    // file that existed: it is written back, not deleted.
    let empty_backup = restore(&installed, Some(&json!({})), Some(&json!({})));
    assert_eq!(empty_backup["delete"], false);
    assert_eq!(rendered(&empty_backup), json!({}));
}

#[test]
fn a_config_guard_never_touched_is_unchanged() {
    let current = json!({"model": "o3", "mcp_servers": {"a": {"command": "npx"}}});
    let answer = restore(&current, Some(&current), None);
    assert_eq!(answer["changed"], false);
    assert_eq!(answer["delete"], false);
    assert_eq!(rendered(&answer), current);
}

#[test]
fn an_empty_server_table_install_wrote_goes_unless_the_backup_had_one() {
    let installed = json!({
        "features": {"hooks": true},
        "hooks": {"PreToolUse": [group("guard", 30)]},
        "mcp_servers": {},
    });
    let created = restore(&installed, None, Some(&json!({})));
    assert_eq!(rendered(&created), json!({}));
    assert_eq!(created["delete"], true);

    let kept = restore(
        &installed,
        Some(&json!({"mcp_servers": {}})),
        Some(&json!({})),
    );
    assert_eq!(rendered(&kept), json!({"mcp_servers": {}}));
    assert_eq!(kept["delete"], false);
}

#[test]
fn user_hooks_left_in_hooks_json_keep_the_hook_feature_on() {
    let backup = json!({"features": {"hooks": false}});
    let installed = json!({
        "features": {"hooks": true},
        "hooks": {"PreToolUse": [group("guard", 30)]},
    });
    let home = Home::new();
    let fields = json!({
        "payload": installed.to_string(),
        "backup": backup.to_string(),
        "hooks": json!({}).to_string(),
        "json_hooks": json!({"PreToolUse": [group("mine", 5)]}).to_string(),
    });
    let answer = home.ask("codex", "uninstall_restore", fields);
    assert_eq!(rendered(&answer), json!({"features": {"hooks": true}}));

    let without = restore(&installed, Some(&backup), Some(&json!({})));
    assert_eq!(rendered(&without), json!({"features": {"hooks": false}}));
}
