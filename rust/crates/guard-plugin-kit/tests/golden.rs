//! Golden tests: each `tests/fixtures/<case>/input` repository against the
//! `check`, `links`, `card` and `package` output recorded in `expected/`.
//!
//! Set `UPDATE_GOLDEN=1` to rewrite the expected files after an intended
//! change, then review the diff.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn fixtures() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut cases: Vec<PathBuf> = fs::read_dir(root)
        .expect("fixtures")
        .map(|entry| entry.expect("fixture").path())
        .filter(|path| path.join("input").is_dir())
        .collect();
    cases.sort();
    cases
}

fn request(command: &str, input: &Path) -> Value {
    let body = json!({"command": command, "root": input.to_string_lossy()});
    let response = guard_plugin_kit::run_request(body.to_string().as_bytes());
    assert_eq!(response["ok"], json!(true), "{command} failed: {response}");
    response["result"].clone()
}

/// The package plan with JSON files inlined and other files as digests. The
/// generator version is masked so a release does not churn every fixture.
fn package(input: &Path) -> Value {
    let outputs = guard_plugin_kit::package_plan(input, &[]).expect("package plan");
    let mut files = BTreeMap::new();
    for output in outputs {
        let value = if output.path.ends_with(".json") {
            let mut value: Value = serde_json::from_slice(&output.content).expect("emitted JSON");
            if output.path == guard_plugin_kit::PROVENANCE_FILE {
                value["generator"]["version"] = json!("<version>");
            }
            value
        } else {
            json!(format!(
                "sha256:{}",
                hex::encode(Sha256::digest(&output.content))
            ))
        };
        files.insert(output.path, value);
    }
    json!(files)
}

fn compare(case: &Path, name: &str, actual: &Value) {
    let path = case.join("expected").join(format!("{name}.json"));
    let rendered = format!(
        "{}\n",
        serde_json::to_string_pretty(actual).expect("render")
    );
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::create_dir_all(path.parent().expect("expected dir")).expect("create expected");
        fs::write(&path, rendered).expect("write expected");
        return;
    }
    let expected =
        fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {}", path.display()));
    assert_eq!(
        rendered,
        expected,
        "{} differs; rerun with UPDATE_GOLDEN=1 and review",
        path.display()
    );
}

#[test]
fn fixtures_match_expected_output() {
    let cases = fixtures();
    assert!(cases.len() >= 5, "fixtures missing");
    for case in cases {
        let input = case.join("input");
        compare(&case, "check", &request("check", &input));
        compare(&case, "links", &request("links", &input));
        compare(&case, "card", &request("card", &input));
        compare(&case, "package", &package(&input));
    }
}

#[test]
fn a_claude_code_plugin_packages_for_at_least_five_runtimes() {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/claude-plugin/input");
    let check = request("check", &input);
    let supported = check["runtimes"]
        .as_array()
        .expect("runtimes")
        .iter()
        .filter(|runtime| runtime["supported"] == json!(true))
        .count();
    assert!(supported >= 5, "{supported} runtimes");
    assert_eq!(check["passed"], json!(true));
}

#[test]
fn literal_secrets_are_flagged_by_name_and_never_echoed() {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/needs-fixes/input");
    let check = request("check", &input).to_string();
    assert!(check.contains("mcp_env_literal_secret"));
    assert!(check.contains("SERVICE_API_KEY"));
    assert!(!check.contains("replace-me-123"));
    let package = package(&input).to_string();
    assert!(!package.contains("replace-me-123"));
}

#[test]
fn bad_requests_are_refused() {
    for body in [
        json!({"command": "check", "root": "relative/path"}),
        json!({"command": "check", "root": "/definitely/not/a/real/dir"}),
        json!({"command": "explode", "root": "/"}),
        json!("not an object"),
    ] {
        let response = guard_plugin_kit::run_request(body.to_string().as_bytes());
        assert_eq!(response["ok"], json!(false), "{body}");
    }
}

fn scratch(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("guard-plugin-kit-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&path);
    fs::create_dir_all(&path).expect("scratch");
    path
}

#[test]
fn package_writes_once_and_refuses_a_non_empty_output() {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/claude-plugin/input");
    let out = scratch("package");
    let body = json!({"command": "package", "root": input.to_string_lossy(), "out_dir": out.to_string_lossy()});
    let first = guard_plugin_kit::run_request(body.to_string().as_bytes());
    assert_eq!(first["result"]["packaged"], json!(true), "{first}");
    assert!(out.join("codex/.codex-plugin/plugin.json").is_file());
    assert!(out
        .join("claude-code/skills/pdf-tools/reference.md")
        .is_file());
    assert!(out.join(guard_plugin_kit::PROVENANCE_FILE).is_file());
    let second = guard_plugin_kit::run_request(body.to_string().as_bytes());
    assert_eq!(second["error"], json!("plugin_kit_output_not_empty"));
    let mut forced = body.clone();
    forced["force"] = json!(true);
    let third = guard_plugin_kit::run_request(forced.to_string().as_bytes());
    assert_eq!(third["result"]["packaged"], json!(true));
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn package_does_not_write_a_failing_plugin() {
    let input = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/needs-fixes/input");
    let out = scratch("failing");
    let body = json!({"command": "package", "root": input.to_string_lossy(), "out_dir": out.join("pkg").to_string_lossy()});
    let response = guard_plugin_kit::run_request(body.to_string().as_bytes());
    assert_eq!(response["result"]["packaged"], json!(false));
    assert!(!out.join("pkg").exists());
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn init_scaffolds_an_empty_folder_and_never_overwrites() {
    let root = scratch("init");
    let body = json!({"command": "init", "root": root.to_string_lossy(), "name": "hello-kit"});
    let response = guard_plugin_kit::run_request(body.to_string().as_bytes());
    assert_eq!(response["result"]["scaffolded"], json!(true), "{response}");
    let check = request("check", &root);
    assert_eq!(check["passed"], json!(true), "{check}");
    let again = guard_plugin_kit::run_request(body.to_string().as_bytes());
    assert_eq!(again["error"], json!("plugin_kit_init_would_overwrite"));
    let _ = fs::remove_dir_all(&root);

    let unnamed = scratch("init-unnamed");
    let body = json!({"command": "init", "root": unnamed.to_string_lossy()});
    let response = guard_plugin_kit::run_request(body.to_string().as_bytes());
    assert_eq!(response["error"], json!("plugin_kit_init_needs_name"));
    let _ = fs::remove_dir_all(&unnamed);
}

#[cfg(unix)]
#[test]
fn symlinked_sources_are_not_followed() {
    let root = scratch("symlink");
    let outside = scratch("symlink-outside");
    fs::create_dir_all(outside.join("skills/leak")).expect("outside");
    fs::write(
        outside.join("skills/leak/SKILL.md"),
        "---\nname: leak\ndescription: Outside the root.\n---\n",
    )
    .expect("outside skill");
    std::os::unix::fs::symlink(outside.join("skills"), root.join("skills")).expect("symlink");
    let check = request("check", &root);
    assert_eq!(check["summary"]["skills"], json!(0), "{check}");
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&outside);
}
