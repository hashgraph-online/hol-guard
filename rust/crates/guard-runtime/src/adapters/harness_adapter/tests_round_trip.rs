//! Install then uninstall gives back a JSON settings file a user already had.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::{after, shim, Home};

const USER_SETTINGS: &str =
    "{\n  \"syntheticUserSetting\": \"keep-me\",\n  \"nested\": {\"value\": 1}\n}\n";
/// Muse refuses a settings file without `schema_version`, so a user's file has one.
const MUSE_USER_SETTINGS: &str =
    "{\n  \"schema_version\": 1,\n  \"syntheticUserSetting\": \"keep-me\"\n}\n";

fn apply(files: &[Value]) {
    for file in files {
        let path = Path::new(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, after(file)).unwrap();
    }
}

fn round_trip(harness: &str, relative: &str, seed: &str, install: Value, uninstall: Value) {
    let home = Home::new();
    let path = home.home().join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, seed).unwrap();
    let answer = home.ask(harness, "prepare_install", install);
    let files = answer["files"]
        .as_array()
        .unwrap_or_else(|| panic!("{answer}"));
    apply(files);
    assert_ne!(
        fs::read_to_string(&path).unwrap(),
        seed,
        "{harness} install changed nothing"
    );
    let answer = home.ask(harness, "prepare_uninstall", uninstall);
    for write in answer["writes"].as_array().into_iter().flatten() {
        if Path::new(write["path"].as_str().unwrap()) == path {
            fs::write(&path, write["text"].as_str().unwrap()).unwrap();
        }
    }
    let restored = fs::read_to_string(&path).unwrap();
    let expected: Value = serde_json::from_str(seed).unwrap();
    let got: Value = serde_json::from_str(&restored).unwrap();
    assert_eq!(got, expected, "{harness}");
}

#[test]
fn muse_install_then_uninstall_returns_the_user_settings() {
    round_trip(
        "muse",
        ".config/muse/settings.json",
        MUSE_USER_SETTINGS,
        json!({"shim": shim(), "hook_argv": ["/g/hol-guard", "/g/managed/bounded-hooks/muse.py"]}),
        json!({}),
    );
}

#[test]
fn omp_install_then_uninstall_returns_the_user_settings() {
    let runtime = json!({"installing_cli": [], "native_hook_runtime": null, "windows": null});
    round_trip(
        "omp",
        ".omp/agent/settings.json",
        USER_SETTINGS,
        json!({"shim": shim(), "runtime": runtime}),
        json!({"runtime": runtime}),
    );
}
