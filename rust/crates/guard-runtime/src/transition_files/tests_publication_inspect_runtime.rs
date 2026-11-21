//! The inspection runs real (shell) runtimes, so it is POSIX only.
#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::dispatch;

const RULES: &str = "b";
const SOURCE: &str = "a";

fn capabilities(protocol: i64, version: &str) -> String {
    json!({
        "protocol_version": protocol,
        "runtime_version": version,
        "rule_digest": RULES.repeat(64),
        "build_sha": SOURCE.repeat(40),
        "target": "test-target",
        "features": ["resident-protocol-v2"],
    })
    .to_string()
}

/// A runtime that answers `capabilities --json` and leaves a marker when run.
fn runtime(directory: &Path, name: &str, answer: &str, mode: u32) -> PathBuf {
    let path = directory.join(name);
    let marker = directory.join(format!("{name}.ran"));
    let script = format!(
        "#!/bin/sh\n: > '{}'\nprintf '%s' '{answer}'\n",
        marker.display()
    );
    fs::write(&path, script).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn ran(directory: &Path, name: &str) -> bool {
    directory.join(format!("{name}.ran")).exists()
}

fn inspect(fields: Value) -> Result<Value, Value> {
    let mut request = json!({
        "op": "publication_inspect_runtime",
        "deadline": 130.0,
        "now": 100.0,
        "mode": "force",
        "binary_override": null,
        "package_version": null,
        "distribution": [],
    });
    for (key, value) in fields.as_object().unwrap() {
        request[key] = value.clone();
    }
    let answer = dispatch(&request).unwrap();
    match answer.get("error") {
        Some(error) => Err(error.clone()),
        None => Ok(answer["value"].clone()),
    }
}

fn reason(error: &Value) -> String {
    error["transition"]
        .as_str()
        .or_else(|| error["integrity"].as_str())
        .unwrap_or_default()
        .to_owned()
}

/// Inspect `selected` as the override of a force-mode launcher whose bundled
/// runtime is absent.
fn inspect_selected(directory: &Path, selected: &Path) -> Result<Value, Value> {
    inspect(json!({
        "binary_override": selected.to_string_lossy(),
        "bundled": directory.join("bundled-absent").to_string_lossy(),
    }))
}

/// The bundled runtime beside the manifest that vouches for it.
fn bundled(directory: &Path, answer: &str, manifest: impl FnOnce(&mut Value)) -> PathBuf {
    let path = runtime(directory, "hol-guard-runtime", answer, 0o700);
    let bytes = fs::read(&path).unwrap();
    let mut body = json!({
        "schema": "hol-guard-native-runtime.v1",
        "protocol_version": 1,
        "package_version": "9.9.9",
        "target": "test-target",
        "platform_tag": "test_tag",
        "source_sha": SOURCE.repeat(40),
        "rule_digest": RULES.repeat(64),
        "runtime_sha256": format!("{:x}", Sha256::digest(&bytes)),
        "runtime_size": bytes.len(),
    });
    manifest(&mut body);
    let manifest_path = directory.join("runtime-manifest.json");
    fs::write(&manifest_path, body.to_string()).unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o444)).unwrap();
    path
}

fn inspect_bundled(path: &Path) -> Result<Value, Value> {
    inspect(json!({
        "mode": "auto",
        "bundled": path.to_string_lossy(),
        "package_version": "9.9.9",
    }))
}

#[test]
fn the_selected_runtime_is_reported_and_left_untouched() {
    let directory = tempfile::tempdir().unwrap();
    let selected = runtime(
        directory.path(),
        "selected",
        &capabilities(1, "9.9.9"),
        0o700,
    );
    let before = fs::metadata(&selected).unwrap();
    let answered = inspect_selected(directory.path(), &selected).unwrap();
    let identity = &answered["identity"];
    assert_eq!(
        identity["path"],
        json!(fs::canonicalize(&selected).unwrap().to_string_lossy())
    );
    assert_eq!(identity["size"], json!(before.len()));
    assert_eq!(
        identity["sha256"],
        json!(format!(
            "{:x}",
            Sha256::digest(fs::read(&selected).unwrap())
        ))
    );
    assert!(ran(directory.path(), "selected"));
    let after = fs::metadata(&selected).unwrap();
    assert_eq!(after.permissions().mode(), before.permissions().mode());
    assert_eq!(after.len(), before.len());
}

#[test]
fn no_runtime_at_any_candidate_is_unavailable() {
    let directory = tempfile::tempdir().unwrap();
    let error = inspect(json!({"bundled": directory.path().join("absent").to_string_lossy()}));
    assert_eq!(
        reason(&error.unwrap_err()),
        "authority_repair_native_unavailable"
    );
}

#[test]
fn an_override_is_honoured_only_in_force_mode_and_only_when_absolute() {
    let directory = tempfile::tempdir().unwrap();
    let selected = runtime(
        directory.path(),
        "selected",
        &capabilities(1, "9.9.9"),
        0o700,
    );
    let absent = directory.path().join("bundled-absent");
    let ask = |mode: &str, override_path: &str| {
        inspect(json!({
            "mode": mode,
            "binary_override": override_path,
            "bundled": absent.to_string_lossy(),
        }))
    };
    assert!(ask("force", &selected.to_string_lossy()).is_ok());
    for (mode, path) in [
        ("auto", selected.to_string_lossy().into_owned()),
        ("force", "selected".to_owned()),
    ] {
        assert_eq!(
            reason(&ask(mode, &path).unwrap_err()),
            "authority_repair_native_unavailable",
            "{mode} {path}"
        );
    }
}

#[test]
fn a_distribution_runtime_is_a_candidate_in_force_mode_only() {
    let directory = tempfile::tempdir().unwrap();
    let distributed = runtime(
        directory.path(),
        "distributed",
        &capabilities(1, "9.9.9"),
        0o700,
    );
    let ask = |mode: &str| {
        inspect(json!({
            "mode": mode,
            "bundled": directory.path().join("bundled-absent").to_string_lossy(),
            "distribution": [distributed.to_string_lossy()],
        }))
    };
    assert!(ask("force").is_ok());
    assert_eq!(
        reason(&ask("auto").unwrap_err()),
        "authority_repair_native_unavailable"
    );
}

#[test]
fn the_first_candidate_that_exists_is_the_one_inspected() {
    let directory = tempfile::tempdir().unwrap();
    let first = runtime(directory.path(), "first", &capabilities(1, "9.9.9"), 0o700);
    let second = runtime(directory.path(), "second", &capabilities(1, "9.9.9"), 0o700);
    let answered = inspect(json!({
        "binary_override": first.to_string_lossy(),
        "bundled": second.to_string_lossy(),
    }))
    .unwrap();
    assert_eq!(
        answered["identity"]["path"],
        json!(fs::canonicalize(&first).unwrap().to_string_lossy())
    );
    assert!(!ran(directory.path(), "second"));
}

#[test]
fn a_runtime_that_cannot_run_is_refused_without_restoring_its_execute_bit() {
    let directory = tempfile::tempdir().unwrap();
    let selected = runtime(
        directory.path(),
        "selected",
        &capabilities(1, "9.9.9"),
        0o400,
    );
    let error = inspect_selected(directory.path(), &selected).unwrap_err();
    assert!(
        reason(&error).starts_with("codex_hook_artifact_"),
        "{error}"
    );
    assert!(!ran(directory.path(), "selected"));
    assert_eq!(
        fs::metadata(&selected).unwrap().permissions().mode() & 0o777,
        0o400
    );
}

#[test]
fn what_the_probe_answers_must_be_a_clean_run_of_the_expected_protocol() {
    let directory = tempfile::tempdir().unwrap();
    let ask = |name: &str, answer: &str| {
        let selected = runtime(directory.path(), name, answer, 0o700);
        reason(&inspect_selected(directory.path(), &selected).unwrap_err())
    };
    assert_eq!(
        ask("old", &capabilities(2, "9.9.9")),
        "native_protocol_mismatch"
    );
    assert_eq!(
        ask("partial", "{\"protocol_version\": 1}"),
        "native_protocol_mismatch"
    );
    assert_eq!(ask("list", "[]"), "native_protocol_mismatch");
    assert_eq!(
        ask("garbled", "not json"),
        "authority_repair_native_inspection_failed"
    );
    assert_eq!(
        ask("empty", ""),
        "authority_repair_native_inspection_failed"
    );
    let failing = directory.path().join("failing");
    fs::write(&failing, "#!/bin/sh\nexit 3\n").unwrap();
    fs::set_permissions(&failing, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        reason(&inspect_selected(directory.path(), &failing).unwrap_err()),
        "authority_repair_native_inspection_failed"
    );
}

#[test]
fn a_bundled_runtime_is_admitted_by_its_manifest_before_it_runs() {
    let directory = tempfile::tempdir().unwrap();
    let path = bundled(directory.path(), &capabilities(1, "9.9.9"), |_| {});
    assert!(inspect_bundled(&path).is_ok());
    assert!(ran(directory.path(), "hol-guard-runtime"));
}

#[test]
fn a_bundled_runtime_with_a_wrong_manifest_never_runs() {
    type Case = (&'static str, fn(&mut Value), &'static str);
    let cases: [Case; 6] = [
        (
            "sha",
            |manifest| manifest["runtime_sha256"] = json!("0".repeat(64)),
            "native_manifest_runtime_mismatch",
        ),
        (
            "size",
            |manifest| manifest["runtime_size"] = json!(1),
            "native_manifest_runtime_mismatch",
        ),
        (
            "version",
            |manifest| manifest["package_version"] = json!("1.0.0"),
            "native_manifest_version_mismatch",
        ),
        (
            "schema",
            |manifest| manifest["schema"] = json!("other"),
            "native_manifest_invalid",
        ),
        (
            "rules",
            |manifest| manifest["rule_digest"] = json!("c".repeat(64)),
            "native_manifest_capabilities_mismatch",
        ),
        (
            "build",
            |manifest| manifest["source_sha"] = json!("d".repeat(40)),
            "native_manifest_capabilities_mismatch",
        ),
    ];
    for (name, edit, expected) in cases {
        let directory = tempfile::tempdir().unwrap();
        let path = bundled(directory.path(), &capabilities(1, "9.9.9"), edit);
        let error = inspect_bundled(&path).unwrap_err();
        assert_eq!(reason(&error), expected, "{name}");
        // Only a capabilities mismatch is found by running the runtime.
        assert_eq!(
            ran(directory.path(), "hol-guard-runtime"),
            expected == "native_manifest_capabilities_mismatch",
            "{name}"
        );
    }
}

#[test]
fn a_bundled_runtime_needs_a_regular_private_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let path = runtime(
        directory.path(),
        "hol-guard-runtime",
        &capabilities(1, "9.9.9"),
        0o700,
    );
    assert_eq!(
        reason(&inspect_bundled(&path).unwrap_err()),
        "native_manifest_missing"
    );
    let manifest = directory.path().join("runtime-manifest.json");
    fs::write(&manifest, b"").unwrap();
    assert_eq!(
        reason(&inspect_bundled(&path).unwrap_err()),
        "native_manifest_invalid"
    );
    fs::write(&manifest, b"{").unwrap();
    assert_eq!(
        reason(&inspect_bundled(&path).unwrap_err()),
        "native_manifest_invalid"
    );
    fs::write(&manifest, vec![b' '; 16 * 1024 + 1]).unwrap();
    assert_eq!(
        reason(&inspect_bundled(&path).unwrap_err()),
        "native_manifest_invalid"
    );
    fs::remove_file(&manifest).unwrap();
    let real = directory.path().join("real.json");
    fs::write(&real, b"{}").unwrap();
    std::os::unix::fs::symlink(&real, &manifest).unwrap();
    assert_eq!(
        reason(&inspect_bundled(&path).unwrap_err()),
        "native_manifest_invalid"
    );
    assert!(!ran(directory.path(), "hol-guard-runtime"));
}

#[test]
fn a_world_or_group_writable_manifest_is_not_trusted() {
    for mode in [0o646, 0o664] {
        let directory = tempfile::tempdir().unwrap();
        let path = bundled(directory.path(), &capabilities(1, "9.9.9"), |_| {});
        let manifest = directory.path().join("runtime-manifest.json");
        fs::set_permissions(&manifest, fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            reason(&inspect_bundled(&path).unwrap_err()),
            "native_manifest_invalid",
            "{mode:o}"
        );
    }
}

#[test]
fn group_write_on_the_manifest_is_trusted_through_a_group_writable_checker() {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o775)).unwrap();
    let path = bundled(directory.path(), &capabilities(1, "9.9.9"), |_| {});
    let manifest = directory.path().join("runtime-manifest.json");
    fs::set_permissions(&manifest, fs::Permissions::from_mode(0o664)).unwrap();
    let checker = directory.path().join("checker.py");
    fs::write(&checker, b"").unwrap();
    fs::set_permissions(&checker, fs::Permissions::from_mode(0o664)).unwrap();
    let ask = |checker: Option<&Path>| {
        inspect(json!({
            "mode": "auto",
            "bundled": path.to_string_lossy(),
            "package_version": "9.9.9",
            "checker": checker.map(|path| path.to_string_lossy().into_owned()),
        }))
    };
    assert!(ask(Some(&checker)).is_ok());
    assert_eq!(reason(&ask(None).unwrap_err()), "native_manifest_invalid");
}

#[test]
fn a_runtime_replaced_while_it_was_inspected_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let selected = directory.path().join("selected");
    let replacement = directory.path().join("selected.new");
    let script = format!(
        "#!/bin/sh\nprintf '%s' '{}'\n/bin/mv '{}' '{}'\n",
        capabilities(1, "9.9.9"),
        replacement.display(),
        selected.display()
    );
    fs::write(&selected, script).unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(&replacement, b"foreign native fixture generation").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    let error = inspect_selected(directory.path(), &selected).unwrap_err();
    assert_eq!(reason(&error), "native_runtime_generation_changed");
    assert_eq!(
        fs::read(&selected).unwrap(),
        b"foreign native fixture generation"
    );
}

#[test]
fn an_expired_parent_deadline_does_not_start_a_probe() {
    let directory = tempfile::tempdir().unwrap();
    let selected = runtime(
        directory.path(),
        "selected",
        &capabilities(1, "9.9.9"),
        0o700,
    );
    for deadline in [json!(100.0), json!(50.0), Value::Null] {
        let error = inspect(json!({
            "deadline": deadline,
            "binary_override": selected.to_string_lossy(),
            "bundled": directory.path().join("bundled-absent").to_string_lossy(),
        }))
        .unwrap_err();
        assert_eq!(reason(&error), "deadline_exceeded");
    }
    assert!(!ran(directory.path(), "selected"));
}

#[test]
fn the_probe_gets_the_shorter_cap_inside_a_long_parent() {
    let directory = tempfile::tempdir().unwrap();
    let selected = directory.path().join("slow");
    fs::write(&selected, "#!/bin/sh\nwhile :; do :; done\n").unwrap();
    fs::set_permissions(&selected, fs::Permissions::from_mode(0o700)).unwrap();
    let started = std::time::Instant::now();
    let error = inspect(json!({
        "deadline": 400.0,
        "binary_override": selected.to_string_lossy(),
        "bundled": directory.path().join("bundled-absent").to_string_lossy(),
    }))
    .unwrap_err();
    assert_eq!(reason(&error), "authority_repair_native_inspection_failed");
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
}

#[test]
fn a_malformed_request_is_refused() {
    for fields in [
        json!({"mode": 5}),
        json!({"distribution": "text"}),
        json!({"bundled": 5}),
        json!({"package_version": 5}),
    ] {
        let error = inspect(fields.clone()).unwrap_err();
        assert_eq!(reason(&error), "files_invalid", "{fields}");
    }
    assert_eq!(reason(&inspect(json!({})).unwrap_err()), "files_invalid");
}
