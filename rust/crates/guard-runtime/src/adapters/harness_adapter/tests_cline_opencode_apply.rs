//! Cline's one-call install and uninstall, the OpenCode config lock, and the
//! spec flags the generic Python client follows for both.

use std::fs;

use serde_json::{json, Value};

use super::super::dispatch;
use super::Home;

fn spec(name: &str) -> Value {
    let answer = dispatch(&json!({"op": "describe"})).unwrap();
    answer["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|adapter| adapter["harness"] == name)
        .unwrap()
        .clone()
}

#[test]
fn describe_names_the_cline_and_opencode_client_flags() {
    let cline = spec("cline");
    assert_eq!(cline["prepare"], "unavailable");
    assert_eq!(cline["warnings_op"], true);
    assert_eq!(cline["frozen_fact"], true);
    assert_eq!(cline["install_timeout"], 90);
    assert_eq!(cline["launch_runner"], "");
    let opencode = spec("opencode");
    assert_eq!(opencode["launch_runner"], "opencode_launch");
    assert_eq!(opencode["warnings_op"], false);
    assert_eq!(opencode["install_timeout"], Value::Null);
    assert_eq!(spec("devin")["launch_runner"], "");
}

#[test]
fn a_cline_uninstall_with_nothing_installed_answers_a_manifest() {
    let home = Home::new();
    let answer = home.ask("cline", "apply_uninstall", json!({}));
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["harness"], "cline");
    assert!(answer.get("refusal").is_none());
}

#[test]
fn a_cline_surface_the_runtime_does_not_know_is_refused() {
    let home = Home::new();
    let answer = home.ask("cline", "apply_uninstall", json!({"surface": "telepathy"}));
    assert_eq!(
        answer["refusal"],
        json!("Unsupported Cline surface: telepathy")
    );
    assert_eq!(answer["events"], json!([]));
}

fn lock_path(home: &Home) -> std::path::PathBuf {
    home.home().join(".config/opencode/.hol-guard-config.lock")
}

#[test]
fn opencode_install_uninstall_and_refresh_wait_out_another_holder_then_report_busy() {
    let home = Home::new();
    let path = lock_path(&home);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let held = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    fs2::FileExt::lock_exclusive(&held).unwrap();
    for op in ["apply_install", "apply_uninstall", "refresh_apply"] {
        let answer = home.ask("opencode", op, json!({}));
        assert_eq!(
            answer["runtime_error"],
            "Another Guard operation is updating OpenCode config; try again shortly",
            "{op}"
        );
    }
    fs2::FileExt::unlock(&held).unwrap();
}

#[cfg(unix)]
#[test]
fn a_symlinked_opencode_lock_is_refused_without_touching_its_target() {
    let home = Home::new();
    let target = home.root.join("target");
    fs::write(&target, "unchanged").unwrap();
    let path = lock_path(&home);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let answer = home.ask("opencode", "apply_uninstall", json!({}));
    assert!(answer.get("refusal").is_some(), "{answer}");
    assert_eq!(fs::read_to_string(&target).unwrap(), "unchanged");
}
