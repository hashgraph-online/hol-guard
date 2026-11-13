//! Pi and Oh My Pi through the `harness_adapter` kind.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::super::{describe, pi, Ctx};
use super::{after, shim, Home};

fn runtime() -> Value {
    json!({"installing_cli": [], "native_hook_runtime": null, "windows": null})
}

fn apply(files: &[Value]) {
    for file in files {
        let path = Path::new(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, after(file)).unwrap();
    }
}

fn scrub(value: &Value, root: &Path) -> Value {
    let text = value.to_string().replace(root.to_str().unwrap(), "<ROOT>");
    serde_json::from_str(&text).unwrap()
}

#[test]
fn detect_sends_the_recorded_pi_detect_request() {
    let vectors: Value = serde_json::from_str(
        &fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/pi/vectors.json"))
            .unwrap(),
    )
    .unwrap();
    let root = PathBuf::from("/vector-root");
    for case in vectors["cases"].as_array().unwrap() {
        let name = case["home"].as_str().unwrap();
        let relative = case["relative"].as_bool().unwrap();
        let base = if relative {
            PathBuf::new()
        } else {
            root.clone()
        };
        let home = base.join(name);
        let workspace = if case["no_workspace"].as_bool().unwrap() {
            Value::Null
        } else if case["workspace_is_home"].as_bool().unwrap() {
            json!(home)
        } else {
            json!(base.join("work"))
        };
        let ctx = Ctx::parse(Some(&json!({
            "home": home,
            "workspace": workspace,
            "guard_home": root.join("guard-home"),
            "home_override_explicit": false,
            "cwd": root,
            "user_home": root.join(name),
            "env": {},
        })))
        .unwrap();
        let spec = describe::spec(case["harness"].as_str().unwrap()).unwrap();
        let request = pi::detect_request(spec, &ctx);
        assert_eq!(scrub(&request, &root), case["args"], "{}", case["name"]);
    }
}

#[test]
fn pi_install_lists_the_extension_and_uninstall_removes_it() {
    let home = Home::new();
    let settings = home.home().join(".pi/agent/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(
        &settings,
        r#"{"extensions": ["npm:custom"], "theme": "dark"}"#,
    )
    .unwrap();
    let extra = json!({"shim": shim(), "runtime": runtime()});
    let answer = home.ask("pi", "prepare_install", extra.clone());
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    let extension = home.home().join(".pi/agent/extensions/hol-guard.ts");
    assert_eq!(files[0]["path"], json!(extension));
    let listed: Value = serde_json::from_str(&after(&files[1])).unwrap();
    assert_eq!(listed["extensions"], json!(["npm:custom", extension]));
    assert_eq!(listed["theme"], "dark");
    assert_eq!(
        home.ask("pi", "extension_current", extra.clone())["current"],
        false
    );
    apply(files);
    assert_eq!(home.ask("pi", "extension_current", extra)["current"], true);

    let uninstall = home.ask("pi", "prepare_uninstall", json!({"runtime": runtime()}));
    assert_eq!(uninstall["deletes"], json!([extension]));
    let kept: Value =
        serde_json::from_str(uninstall["writes"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(kept["extensions"], json!(["npm:custom"]));
    assert_eq!(uninstall["finish"]["tail"], json!([]));
}

#[test]
fn pi_install_refuses_settings_that_are_not_an_object() {
    let home = Home::new();
    let settings = home.home().join(".omp/agent/settings.json");
    fs::create_dir_all(settings.parent().unwrap()).unwrap();
    fs::write(&settings, "[]").unwrap();
    let request = json!({
        "harness": "omp",
        "op": "prepare_install",
        "context": home.context(json!({"PATH": ""})),
        "shim": shim(),
        "runtime": runtime(),
    });
    let answer = super::super::dispatch(&request).unwrap();
    assert!(
        answer
            .to_string()
            .contains("Oh My Pi settings must be a JSON object."),
        "{answer}"
    );
}

#[test]
fn pi_uninstall_retires_the_legacy_combined_omp_extension() {
    let home = Home::new();
    let settings = home.home().join(".omp/agent/settings.json");
    let legacy = home.home().join(".omp/agent/extensions/hol-guard.ts");
    let source = home.ask(
        "pi",
        "extension_source",
        json!({"variant": "previous", "config_path": settings, "runtime": runtime()}),
    )["source"]
        .as_str()
        .unwrap()
        .to_owned();
    fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    fs::write(&legacy, source).unwrap();
    fs::write(&settings, json!({"extensions": [legacy]}).to_string()).unwrap();
    let install = json!({
        "active": true,
        "manifest": {"config_path": home.home().join(".pi/agent/extensions/hol-guard.ts")},
    });
    let verified = home.ask(
        "pi",
        "legacy_omp_verified",
        json!({"managed_install": install, "runtime": runtime()}),
    );
    assert_eq!(verified["verified"], true);

    let uninstall = home.ask("pi", "prepare_uninstall", json!({"runtime": runtime()}));
    assert_eq!(uninstall["deletes"], json!([legacy]));
    assert_eq!(uninstall["finish"]["tail"].as_array().unwrap().len(), 1);
    let finished = home.ask(
        "pi",
        "finish_uninstall",
        json!({"shim": shim(), "finish": uninstall["finish"].clone()}),
    );
    let manifest: Value = serde_json::from_str(finished["manifest"].as_str().unwrap()).unwrap();
    let notes = manifest["notes"].as_array().unwrap();
    assert_eq!(notes.len(), 3, "{manifest}");
}
