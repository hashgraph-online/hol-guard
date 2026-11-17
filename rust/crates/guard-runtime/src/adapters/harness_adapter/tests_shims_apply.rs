//! `apply_guard_shims` and `apply_plan`: prepared launchers and adapter
//! plans published in the same native call that rendered them.

use std::fs;

use serde_json::{json, Value};

use super::Home;

fn interpreter() -> Value {
    json!({
        "executable": "/opt/python/bin/python3",
        "frozen": false,
        "package_interpreter": "/opt/python/bin/python3",
        "python_flags": ["-I", "-P"],
        "import_root": "/opt/site",
        "launcher_env": [],
    })
}

fn transition() -> Value {
    json!({"package_roots": [], "budget": null})
}

#[test]
fn both_cursor_launchers_publish_in_one_call() {
    let home = Home::new();
    fs::create_dir_all(home.guard().join("bin")).unwrap();
    let answer = home.ask(
        "cursor",
        "apply_guard_shims",
        json!({
            "shims": [
                {"harness": "cursor", "launcher_name": "cursor-agent", "display_name": "Cursor CLI (cursor-agent)"},
                {"harness": "cursor", "launcher_name": "cursor", "display_name": "Cursor CLI (cursor agent)"},
            ],
            "interpreter": interpreter(),
            "profile": null,
            "transition": transition(),
        }),
    );
    assert_eq!(answer["publish"]["ok"], json!(true), "{answer}");
    assert_eq!(answer["profile"], Value::Null);
    let shims = answer["shims"].as_array().unwrap();
    assert_eq!(shims.len(), 2);
    for shim in shims {
        let manifest: Value = serde_json::from_str(shim.as_str().unwrap()).unwrap();
        let path = manifest["shim_path"].as_str().unwrap();
        assert!(fs::read_to_string(path)
            .unwrap()
            .starts_with("#!/opt/python/bin/python3\n"));
    }
}

#[test]
fn nothing_to_publish_writes_nothing() {
    let home = Home::new();
    let answer = home.ask(
        "cursor",
        "apply_guard_shims",
        json!({"shims": [], "interpreter": interpreter(), "profile": null, "transition": transition()}),
    );
    assert_eq!(answer["publish"], json!({"ok": true, "events": []}));
    assert_eq!(answer["shims"], json!([]));
}

#[test]
fn a_plan_publishes_through_apply_plan() {
    let home = Home::new();
    fs::create_dir_all(home.home().join(".kimi-code")).unwrap();
    let answer = home.ask(
        "kimi",
        "apply_plan",
        json!({
            "plan_op": "prepare_install",
            "removals": false,
            "hook_argv": ["/py", "-m", "guard hook"],
            "shim": super::shim(),
            "transition": transition(),
        }),
    );
    assert_eq!(answer["publish"]["ok"], json!(true), "{answer}");
    assert!(answer["manifest"].is_string(), "{answer}");
    let config = fs::read_to_string(home.home().join(".kimi-code/config.toml")).unwrap();
    assert!(config.contains("'guard hook'"), "{config}");
}

#[test]
fn a_plan_whose_cli_cannot_be_attested_refuses_before_any_write() {
    let home = Home::new();
    let answer = home.ask(
        "cursor",
        "apply_plan",
        json!({"plan_op": "hooks_install", "removals": true, "transition": transition()}),
    );
    // The runtime attests the Guard CLI itself now; a host without one refuses.
    assert!(answer["runtime_error"].is_string(), "{answer}");
    assert!(!home.home().join(".cursor/hooks.json").exists());
}
