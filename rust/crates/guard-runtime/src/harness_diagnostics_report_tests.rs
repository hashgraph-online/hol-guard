use serde_json::{json, Value};

use super::*;

const SHIM: &str = "python -m codex_plugin_scanner.cli guard run stubtool %*\r\n";
const CONFIG: &str = "/home/user/.stubtool/config.json";

fn shown(artifact_type: &str, command: Option<&str>, args: &[&str]) -> Value {
    json!({
        "artifact_type": artifact_type,
        "command": command,
        "args": [args],
        "harness": "stubtool",
        "serialized": { "name": "shown", "args": [args] },
    })
}

fn request(guard_home: &str, detection: Value, own: Value, probe: Value) -> Fields {
    let mut fields = Fields::new();
    for (key, value) in [
        ("op", json!("diagnostics")),
        ("harness", json!("stubtool")),
        ("executable", json!("stubcli")),
        ("command_absence_proves_uninstalled", json!(true)),
        ("guard_home", json!(guard_home)),
        ("names", json!(["stubtool"])),
        ("warnings", own),
        ("runtime_probe", probe),
        ("detection", detection),
    ] {
        fields.insert(key.to_owned(), value);
    }
    fields
}

fn found(installed: bool, command_available: bool, config: &[&str], artifacts: &[Value]) -> Value {
    json!({
        "installed": installed,
        "command_available": command_available,
        "config_paths": [config],
        "artifacts": [artifacts],
        "warnings": [["from the adapter"]],
    })
}

fn report(fields: &Fields) -> Value {
    answer(fields).expect("diagnostics")["diagnostics"].clone()
}

fn guard_home_with_shim() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::write(bin.join("guard-stubtool"), SHIM).unwrap();
    home
}

#[test]
fn an_unmanaged_config_reports_partial_with_the_adapters_own_warning_first() {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().to_string_lossy().into_owned();
    let probe = json!({ "ok": true, "reported_artifacts": 3 });
    let fields = request(
        &guard_home,
        found(
            false,
            true,
            &[CONFIG],
            &[shown("mcp_server", Some("x"), &["a"])],
        ),
        Value::Null,
        probe.clone(),
    );
    let out = report(&fields);
    assert_eq!(out["harness"], "stubtool");
    assert_eq!(out["installed"], false);
    assert_eq!(out["setup_status"], "partial");
    assert_eq!(out["command_available"], true);
    assert_eq!(out["config_paths"], json!([CONFIG]));
    assert_eq!(
        out["artifacts"],
        json!([{ "name": "shown", "args": ["a"] }])
    );
    assert_eq!(out["runtime_probe"], probe);
    assert_eq!(
        out["warnings"],
        json!([
            "from the adapter",
            "stubtool config was found, but Guard is not installed for this harness. \
             Run `hol-guard install stubtool` to enable protection."
        ])
    );
}

#[test]
fn a_launcher_shim_is_a_managed_artifact_and_marks_the_harness_installed() {
    let home = guard_home_with_shim();
    let guard_home = home.path().to_string_lossy().into_owned();
    let shim = home.path().join("bin").join("guard-stubtool");
    let fields = request(
        &guard_home,
        found(false, true, &[], &[]),
        Value::Null,
        Value::Null,
    );
    let out = report(&fields);
    assert_eq!(out["installed"], true);
    assert_eq!(out["setup_status"], "active");
    assert_eq!(out["runtime_probe"], Value::Null);
    assert_eq!(out["warnings"], json!(["from the adapter"]));
    assert_eq!(
        out["artifacts"],
        json!([{
            "artifact_id": "stubtool:guard-launcher-shim",
            "name": "guard-stubtool",
            "harness": "stubtool",
            "artifact_type": "guard_launcher_shim",
            "source_scope": "guard",
            "config_path": shim.to_string_lossy(),
            "command": shim.to_string_lossy(),
            "args": [],
            "url": null,
            "transport": null,
            "publisher": null,
            "metadata": { "shim_dir": home.path().join("bin").to_string_lossy() },
        }])
    );
}

#[test]
fn a_launcher_without_its_command_stays_broken_and_visible() {
    let home = guard_home_with_shim();
    let guard_home = home.path().to_string_lossy().into_owned();
    let fields = request(
        &guard_home,
        found(false, false, &[CONFIG], &[]),
        Value::Null,
        Value::Null,
    );
    assert_eq!(report(&fields)["setup_status"], "broken");
}

#[test]
fn a_harness_that_words_its_own_warnings_replaces_the_added_ones() {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().to_string_lossy().into_owned();
    let fields = request(
        &guard_home,
        found(false, true, &[CONFIG], &[]),
        json!([["its own"]]),
        Value::Null,
    );
    let out = report(&fields);
    assert_eq!(out["warnings"], json!(["its own"]));
    assert_eq!(out["setup_status"], "partial");
}

#[test]
fn a_report_wider_than_one_native_array_joins_back_in_order() {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().to_string_lossy().into_owned();
    let mut fields = request(
        &guard_home,
        found(true, true, &[], &[]),
        Value::Null,
        Value::Null,
    );
    fields.get_mut("detection").unwrap()["config_paths"] = json!([["a", "b"], ["c"]]);
    fields.get_mut("detection").unwrap()["artifacts"] = json!([
        [shown("hook", Some("hol-guard"), &["hook"])],
        [shown("mcp_server", None, &[])]
    ]);
    let out = report(&fields);
    assert_eq!(out["config_paths"], json!(["a", "b", "c"]));
    assert_eq!(out["artifacts"].as_array().unwrap().len(), 2);
    assert_eq!(out["setup_status"], "active");
}

#[test]
fn a_malformed_report_request_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().to_string_lossy().into_owned();
    let good = request(
        &guard_home,
        found(true, true, &[], &[]),
        Value::Null,
        Value::Null,
    );
    let mut broken: Vec<Fields> = Vec::new();
    let mut with = |key: &str, value: Value| {
        let mut fields = good.clone();
        fields.insert(key.to_owned(), value);
        broken.push(fields);
    };
    with("harness", json!(7));
    with("command_absence_proves_uninstalled", json!("yes"));
    with("warnings", json!(["flat"]));
    with("runtime_probe", json!("timed out"));
    with("names", json!("stubtool"));
    with("detection", json!([]));
    with("detection", {
        let mut detection = found(true, true, &[], &[]);
        detection["installed"] = json!("yes");
        detection
    });
    with("detection", {
        let mut detection = found(true, true, &[], &[]);
        detection["artifacts"] = json!([[{
            "artifact_type": "hook", "command": null, "args": [[]], "harness": "stubtool"
        }]]);
        detection
    });
    with("detection", {
        let mut detection = found(true, true, &[], &[]);
        detection.as_object_mut().unwrap().remove("warnings");
        detection
    });
    with("extra", json!(true));
    for fields in broken {
        assert_eq!(answer(&fields), Err(ERR_INVALID), "{fields:?}");
    }
}
