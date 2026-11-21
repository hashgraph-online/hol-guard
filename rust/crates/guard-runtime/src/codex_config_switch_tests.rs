use std::fs;

use serde_json::{json, Value};
use tempfile::TempDir;

use super::*;

fn homes(root: &TempDir) -> Homes {
    let home_dir = root.path().join("home");
    fs::create_dir_all(home_dir.join(".codex")).unwrap();
    fs::write(home_dir.join(".codex/config.toml"), "model = \"x\"\n").unwrap();
    Homes {
        guard_home: root.path().join("guard"),
        home_dir,
        codex_home: None,
    }
}

fn config_text(homes: &Homes) -> String {
    fs::read_to_string(homes.home_dir.join(".codex/config.toml")).unwrap()
}

#[test]
fn lean_mode_writes_the_size_under_the_install_lock_and_takes_it_back() {
    let root = TempDir::new().unwrap();
    let homes = homes(&root);
    assert_eq!(status(Switch::Lean, &homes).unwrap()["state"], "off");
    let on = change(Switch::Lean, &homes, "enable", Some(&json!(120_000))).unwrap();
    assert_eq!(on["state"], "on", "{on}");
    assert!(config_text(&homes).contains("model_auto_compact_token_limit = 120000"));
    assert!(config_text(&homes).contains("model = \"x\""));
    let off = change(Switch::Lean, &homes, "disable", None).unwrap();
    assert_eq!(off["state"], "off", "{off}");
    assert!(!config_text(&homes).contains("model_auto_compact_token_limit"));
    // The lock was given back: a second change does not wait for it.
    change(Switch::Lean, &homes, "enable", Some(&json!(50_000))).unwrap();
}

#[test]
fn a_size_guard_refuses_changes_nothing() {
    let root = TempDir::new().unwrap();
    let homes = homes(&root);
    for (limit, code) in [
        (None, "codex_lean_limit_required"),
        (Some(json!(10)), "codex_lean_limit_invalid"),
        (Some(json!("big")), "codex_lean_limit_invalid"),
    ] {
        assert_eq!(
            change(Switch::Lean, &homes, "enable", limit.as_ref()),
            Err(code.to_owned())
        );
    }
    assert_eq!(config_text(&homes), "model = \"x\"\n");
}

#[test]
fn short_replies_turn_on_and_off() {
    let root = TempDir::new().unwrap();
    let homes = homes(&root);
    let on = change(Switch::ShortReplies, &homes, "enable", None).unwrap();
    assert_eq!(on["state"], "on", "{on}");
    assert!(config_text(&homes).contains("developer_instructions"));
    let off = change(Switch::ShortReplies, &homes, "disable", None).unwrap();
    assert_eq!(off["state"], "off", "{off}");
    assert!(!config_text(&homes).contains("developer_instructions"));
    assert_eq!(
        status(Switch::ShortReplies, &homes).unwrap()["state"],
        "off"
    );
    // A user's "off" holds when the settings save asks for the default again.
    let ensured = change(Switch::ShortReplies, &homes, "ensure", None).unwrap();
    assert_eq!(ensured["state"], "off", "{ensured}");
    let fresh = TempDir::new().unwrap();
    let fresh = self::homes(&fresh);
    let ensured = change(Switch::ShortReplies, &fresh, "ensure", None).unwrap();
    assert_eq!(ensured["state"], "on", "{ensured}");
}

#[test]
fn the_cli_op_answers_the_state_and_the_text() {
    let root = TempDir::new().unwrap();
    let homes = homes(&root);
    let guard_home = homes.guard_home.to_string_lossy().into_owned();
    let ask = |args: Value| dispatch(&args, &guard_home).unwrap();
    let home_dir = homes.home_dir.to_string_lossy().into_owned();
    let on = ask(json!({
        "switch": "lean", "action": "enable", "home_dir": home_dir,
        "limit": 100_000, "text": true,
    }));
    assert_eq!(on["ok"], true, "{on}");
    assert_eq!(
        on["text"],
        "Guard set Codex to sum up older turns once a session passes 100,000 tokens.\n\
Summing up sooner keeps the chat small but can raise the bill: Codex reads again, \
at full price, the files it had already read.\n\
Remove it with: hol-guard context lean off\n"
    );
    let refused = ask(json!({
        "switch": "lean", "action": "enable", "home_dir": home_dir, "text": true,
    }));
    assert_eq!(refused["ok"], false);
    assert_eq!(refused["code"], "codex_lean_limit_required");
    assert!(refused["text"].as_str().unwrap().starts_with("Pick a size"));
    for bad in [
        json!({"switch": "lean", "action": "ensure", "home_dir": home_dir}),
        json!({"switch": "other", "action": "status", "home_dir": home_dir}),
        json!({"switch": "lean", "action": "status", "home_dir": "relative"}),
    ] {
        assert!(dispatch(&bad, &guard_home).is_err(), "{bad}");
    }
}

#[test]
fn a_users_own_limit_is_named_and_left_alone() {
    let state = json!({"state": "yours", "limit": 64000});
    assert_eq!(
        render_lean(&state),
        "Your Codex config already sets model_auto_compact_token_limit = 64000. Guard left it as it is.\n"
    );
    assert!(render_lean(&json!({"state": "off"})).starts_with("Off. Codex sums up"));
    assert_eq!(
        render_lean_failure(BUSY),
        "Guard could not change the Codex config (codex_config_busy). Nothing was changed."
    );
}
