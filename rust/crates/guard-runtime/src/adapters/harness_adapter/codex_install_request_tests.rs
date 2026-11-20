use serde_json::{json, Map, Value};

use super::super::{Ctx, Failure};
use super::{detect_legacy, host_syntax, legacy_tail};

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_owned()).collect()
}

#[test]
fn a_native_launcher_prefix_is_dropped_before_the_tail() {
    let wrapped = argv(&["/g/rt", "codex-hook-bridge", "/py", "bridge.py", "--home"]);
    assert_eq!(legacy_tail(&wrapped), ["bridge.py", "--home"]);
}

#[test]
fn the_current_registration_is_its_own_identity() {
    let current = argv(&["/g/rt", "codex-hook-bridge", "/c/config.toml"]);
    assert_eq!(
        legacy_tail(&current),
        ["codex-hook-bridge", "/c/config.toml"]
    );
    let empty_runtime = argv(&["", "codex-hook-bridge", "a", "b"]);
    assert_eq!(legacy_tail(&empty_runtime), ["codex-hook-bridge", "a", "b"]);
    assert!(legacy_tail(&[]).is_empty());
    assert!(legacy_tail(&argv(&["only"])).is_empty());
}

fn ctx() -> Ctx {
    Ctx::parse(Some(&json!({
        "home": "/h",
        "guard_home": "/h/.hol-guard",
        "cwd": "/h",
        "user_home": "/h",
        "env": {},
    })))
    .unwrap()
}

#[test]
fn this_hosts_command_syntax_fills_what_a_request_leaves_out() {
    let ctx = ctx();
    let bare = Map::new();
    let filled = host_syntax(&ctx, &bare);
    assert_eq!(filled["windows"], json!(ctx.windows));
    assert_eq!(filled["long_paths"], json!({}));
    let named = json!({"windows": !ctx.windows, "long_paths": {"a": "b"}});
    let named = named.as_object().unwrap();
    let kept = host_syntax(&ctx, named);
    assert_eq!(kept["windows"], json!(!ctx.windows));
    assert_eq!(kept["long_paths"], json!({"a": "b"}));
}

#[test]
fn a_legacy_block_needs_a_launch() {
    let none: Value = json!({});
    assert!(matches!(
        detect_legacy(&ctx(), none.as_object().unwrap()),
        Err(Failure::Invalid)
    ));
}
