//! `apply_install`: the launcher shims and the adapter plan, published in
//! one call as `NativeHarnessAdapter.install` published them.

use std::fs;

use serde_json::{json, Value};

use super::Home;

fn request() -> Value {
    json!({
        "hook_argv": ["/py", "-m", "guard hook"],
        "interpreter": {
            "executable": "/opt/python/bin/python3",
            "frozen": false,
            "package_interpreter": "/opt/python/bin/python3",
            "python_flags": ["-I", "-P"],
            "import_root": "/opt/site",
            "launcher_env": [],
        },
        "transition": {"package_roots": [], "budget": null},
    })
}

#[test]
fn install_publishes_the_launchers_and_the_hook_together() {
    let home = Home::new();
    fs::create_dir_all(home.guard().join("bin")).unwrap();
    fs::create_dir_all(home.home().join(".kimi-code")).unwrap();
    let answer = home.ask("kimi", "apply_install", request());
    assert_eq!(answer["publish"]["ok"], json!(true), "{answer}");
    let events = answer["publish"]["events"].as_array().unwrap();
    assert!(events.iter().all(|event| event.get("written").is_none()));
    let launcher = home.guard().join("bin").join("guard-kimi");
    assert!(fs::read_to_string(&launcher)
        .unwrap()
        .starts_with("#!/opt/python/bin/python3\n"));
    let config = fs::read_to_string(home.home().join(".kimi-code/config.toml")).unwrap();
    assert!(config.contains("'guard hook'"), "{config}");
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["shim_path"], json!(launcher));
}

#[cfg(unix)]
#[test]
fn a_linked_launcher_refuses_the_plan_before_any_write() {
    let home = Home::new();
    let bin = home.guard().join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::create_dir_all(home.home().join(".kimi-code")).unwrap();
    std::os::unix::fs::symlink(home.root.join("elsewhere"), bin.join("guard-kimi")).unwrap();
    let answer = home.ask("kimi", "apply_install", request());
    assert_eq!(
        answer["publish"],
        json!({"error": {"transition": "file_target_invalid"}, "events": []})
    );
    assert!(!home.home().join(".kimi-code/config.toml").exists());
}
