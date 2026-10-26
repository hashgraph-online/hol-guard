use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{expand_placeholders, normalize, Environment};
use crate::runtime_identity_probe::run_command;

pub(crate) fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

pub(crate) fn text(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// Run one request through the real command and return its result.
pub(crate) fn run(request: Value) -> Value {
    let reply = run_command(request.to_string().as_bytes()).expect("parsed");
    assert_eq!(reply["ok"], true, "{reply}");
    reply["result"].clone()
}

fn run_error(request: Value) -> String {
    let reply = run_command(request.to_string().as_bytes()).expect("parsed");
    assert_eq!(reply["ok"], false, "{reply}");
    reply["error"].as_str().unwrap().to_owned()
}

pub(crate) fn spec(command: &str, launch_dir: &Path) -> Value {
    json!({"command": command, "launch_dir": text(launch_dir)})
}

fn spec_with_path(command: &str, launch_dir: &Path, path: &str) -> Value {
    json!({"command": command, "launch_dir": text(launch_dir), "configured_path": path})
}

/// The `(path, role)` targets of launch `index`.
pub(crate) fn targets(result: &Value, index: usize) -> Vec<(String, String)> {
    result["launches"][index]["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|target| {
            (
                target["path"].as_str().unwrap().to_owned(),
                target["role"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

pub(crate) fn paths_of(result: &Value, index: usize) -> Vec<String> {
    targets(result, index)
        .into_iter()
        .map(|(path, _)| path)
        .collect()
}

#[cfg(unix)]
pub(crate) fn executable(root: &Path, relative: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(unix)]
pub(crate) fn fifo(root: &Path, relative: &str) -> PathBuf {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let status = std::process::Command::new("mkfifo")
        .args(["-m", "755"])
        .arg(&path)
        .status()
        .expect("mkfifo runs");
    assert!(status.success());
    path
}

#[cfg(unix)]
#[test]
fn bare_command_resolves_through_the_given_path_to_the_real_file() {
    let dir = tempfile::tempdir().unwrap();
    let node = executable(dir.path(), "bin/node", "binary\n");
    let decoy = executable(dir.path(), "other/node", "binary\n");
    let result = run(json!({
        "launches": [spec("node", dir.path())],
        "environment": env(&[("PATH", text(&dir.path().join("bin")))]),
    }));

    assert_eq!(
        targets(&result, 0),
        [(text(&node).to_owned(), "launch".to_owned())]
    );
    assert_eq!(result["launches"][0]["state"], "resolved");
    assert_eq!(result["candidate_limit_reached"], false);
    let observed = result["observations"].as_array().unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0]["requested_path"], text(&node));
    assert_ne!(observed[0]["requested_path"], text(&decoy));
    assert_eq!(result["locations"][0]["state"], "present");
}

#[cfg(unix)]
#[test]
fn server_configured_path_wins_over_the_process_path() {
    let dir = tempfile::tempdir().unwrap();
    executable(dir.path(), "process/node", "binary\n");
    let server_node = executable(dir.path(), "server/node", "binary\n");
    let result = run(json!({
        "launches": [spec_with_path("node", dir.path(), text(&dir.path().join("server")))],
        "environment": env(&[("PATH", text(&dir.path().join("process")))]),
    }));

    assert_eq!(paths_of(&result, 0), [text(&server_node)]);
}

#[cfg(unix)]
#[test]
fn path_placeholder_expands_and_keeps_the_servers_own_directories_first() {
    let dir = tempfile::tempdir().unwrap();
    let process_node = executable(dir.path(), "process/node", "binary\n");
    let server_node = executable(dir.path(), "opt/node22/node", "binary\n");
    let process = env(&[("PATH", text(&dir.path().join("process")))]);
    let prepend = format!("{}:${{PATH}}", dir.path().join("opt/node22").display());
    let result = run(json!({
        "launches": [
            spec_with_path("node", dir.path(), &prepend),
            spec_with_path("node", dir.path(), "$PATH:/opt/extra"),
        ],
        "environment": process,
    }));

    assert_eq!(paths_of(&result, 0), [text(&server_node)]);
    assert_eq!(paths_of(&result, 1), [text(&process_node)]);
}

#[test]
fn placeholders_cover_all_three_spellings_and_unknown_means_unresolved() {
    let vars = env(&[("PATH", "/usr/bin"), ("Home", "/h")]);
    let env = Environment(&vars);

    assert_eq!(
        expand_placeholders("$PATH:/x", &env).as_deref(),
        Some("/usr/bin:/x")
    );
    assert_eq!(
        expand_placeholders("${PATH}:/x", &env).as_deref(),
        Some("/usr/bin:/x")
    );
    assert_eq!(
        expand_placeholders("%PATH%;/x", &env).as_deref(),
        Some("/usr/bin;/x")
    );
    assert_eq!(
        expand_placeholders("$HOME/bin", &env).as_deref(),
        Some("/h/bin")
    );
    assert_eq!(
        expand_placeholders("/plain", &env).as_deref(),
        Some("/plain")
    );
    assert_eq!(
        expand_placeholders("${NO_SUCH_VARIABLE_FOR_GUARD}/bin:${PATH}", &env),
        None
    );
}

#[cfg(unix)]
#[test]
fn path_with_a_variable_the_request_lacks_is_unresolved_not_guessed() {
    let dir = tempfile::tempdir().unwrap();
    executable(dir.path(), "process/node", "binary\n");
    let result = run(json!({
        "launches": [spec_with_path(
            "node", dir.path(), "${NO_SUCH_VARIABLE_FOR_GUARD}/bin:${PATH}"
        )],
        "environment": env(&[("PATH", text(&dir.path().join("process")))]),
    }));

    assert!(targets(&result, 0).is_empty());
    assert_eq!(result["launches"][0]["state"], "unresolved");
    assert_eq!(result["launches"][0]["lookup"], "search_path");
}

#[cfg(unix)]
#[test]
fn relative_path_entries_resolve_against_the_launch_directory() {
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    let local = executable(&workspace, "node_modules/.bin/node", "binary\n");
    let result = run(json!({
        "launches": [spec("node", &workspace)],
        "environment": env(&[("PATH", "node_modules/.bin")]),
    }));

    assert_eq!(paths_of(&result, 0), [text(&local)]);
    assert!(Path::new(&paths_of(&result, 0)[0]).is_absolute());
}

#[cfg(unix)]
#[test]
fn empty_path_entry_means_the_launch_directory() {
    let dir = tempfile::tempdir().unwrap();
    let local = executable(dir.path(), "node", "binary\n");
    let result = run(json!({
        "launches": [spec("node", dir.path())],
        "environment": env(&[("PATH", "/nonexistent-dir:")]),
    }));

    assert_eq!(paths_of(&result, 0), [text(&local)]);
}

#[cfg(unix)]
#[test]
fn absolute_and_launch_directory_relative_commands() {
    let dir = tempfile::tempdir().unwrap();
    let absolute = executable(dir.path(), "abs/runner", "binary\n");
    let workspace = dir.path().join("workspace");
    let local = executable(&workspace, "tools/serve", "binary\n");
    let result = run(json!({
        "launches": [
            spec(text(&absolute), &workspace),
            spec("./tools/serve", &workspace),
            spec("./tools/missing", &workspace),
            spec("   ", &workspace),
        ],
        "environment": env(&[("PATH", "/usr/bin:/bin")]),
    }));

    assert_eq!(paths_of(&result, 0), [text(&absolute)]);
    assert_eq!(paths_of(&result, 1), [text(&local)]);
    assert_eq!(result["launches"][2]["state"], "unresolved");
    assert_eq!(result["launches"][2]["lookup"], "configured_path");
    assert_eq!(result["launches"][3]["state"], "unresolved");
    assert_eq!(result["launches"][3]["lookup"], "search_path");
}

#[test]
fn missing_explicit_path_keeps_its_kind_and_a_missing_name_is_a_path_lookup() {
    let dir = tempfile::tempdir().unwrap();
    let gone = dir.path().join("gone/serve");
    let result = run(json!({
        "launches": [spec(text(&gone), dir.path()), spec("no-such-tool", dir.path())],
        "environment": env(&[("PATH", text(dir.path()))]),
    }));

    assert_eq!(result["launches"][0]["lookup"], "configured_path");
    assert_eq!(result["launches"][1]["lookup"], "search_path");
    assert_eq!(result["observations"], json!([]));
}

#[cfg(unix)]
#[test]
fn home_prefix_follows_the_shared_home_variable() {
    let dir = tempfile::tempdir().unwrap();
    let tool = executable(dir.path(), "bin/serve", "binary\n");
    let result = run(json!({
        "launches": [spec("~/bin/serve", Path::new("/")), spec("~other/bin/serve", Path::new("/"))],
        "environment": env(&[("HOME", text(dir.path()))]),
    }));

    assert_eq!(paths_of(&result, 0), [text(&tool)]);
    assert_eq!(result["launches"][1]["state"], "unresolved");
}

#[cfg(unix)]
#[test]
fn without_a_search_path_a_bare_command_is_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    executable(dir.path(), "node", "binary\n");
    let result = run(json!({"launches": [spec("node", dir.path())]}));

    assert_eq!(result["launches"][0]["state"], "unresolved");
}

#[cfg(unix)]
#[test]
fn a_file_without_an_execute_bit_is_not_a_launch() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let plain = executable(dir.path(), "bin/node", "binary\n");
    fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
    let result = run(json!({
        "launches": [spec("node", dir.path())],
        "environment": env(&[("PATH", text(&dir.path().join("bin")))]),
    }));

    assert_eq!(result["launches"][0]["state"], "unresolved");
}

#[cfg(unix)]
#[test]
fn executable_fifo_on_the_path_is_neither_opened_nor_a_candidate() {
    let dir = tempfile::tempdir().unwrap();
    fifo(dir.path(), "bin/node");
    let result = run(json!({
        "launches": [spec_with_path("node", dir.path(), text(&dir.path().join("bin")))],
        "environment": env(&[("PATH", "")]),
    }));

    assert_eq!(result["launches"][0]["state"], "unresolved");
    assert_eq!(result["observations"], json!([]));
}

#[cfg(unix)]
#[test]
fn fifo_launch_command_is_unresolved_and_never_opened() {
    let dir = tempfile::tempdir().unwrap();
    let pipe = fifo(dir.path(), "serve");
    let result = run(json!({"launches": [spec(text(&pipe), dir.path())]}));

    assert_eq!(result["launches"][0]["state"], "unresolved");
    assert_eq!(result["launches"][0]["lookup"], "configured_path");
}
#[cfg(unix)]
#[test]
fn servers_sharing_an_executable_share_one_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let node = executable(dir.path(), "bin/node", "binary\n");
    let result = run(json!({
        "launches": [spec("node", dir.path()), spec("node", dir.path())],
        "environment": env(&[("PATH", text(&dir.path().join("bin")))]),
    }));

    assert_eq!(paths_of(&result, 0), [text(&node)]);
    assert_eq!(paths_of(&result, 1), [text(&node)]);
    assert_eq!(result["observations"].as_array().unwrap().len(), 1);
    assert_eq!(result["candidate_limit_reached"], false);
}

#[cfg(unix)]
#[test]
fn candidate_count_is_capped_and_reported() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let mut launches = Vec::new();
    for index in 0..5 {
        executable(&bin, &format!("tool{index}"), "binary\n");
        launches.push(spec(&format!("tool{index}"), dir.path()));
    }
    let result = run(json!({
        "launches": launches,
        "candidate_limit": 3,
        "environment": env(&[("PATH", text(&bin))]),
    }));

    assert_eq!(result["observations"].as_array().unwrap().len(), 3);
    assert_eq!(result["candidate_limit_reached"], true);
    // A launch the cap dropped is still resolved, not reported missing.
    assert_eq!(result["launches"][4]["state"], "resolved");
    assert!(targets(&result, 4).is_empty());
}

#[cfg(unix)]
#[test]
fn candidates_are_described_in_sorted_path_order() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    let zed = executable(&bin, "zed", "binary\n");
    let alpha = executable(&bin, "alpha", "binary\n");
    let result = run(json!({
        "launches": [spec("zed", dir.path()), spec("alpha", dir.path())],
        "environment": env(&[("PATH", text(&bin))]),
    }));

    let order: Vec<&str> = result["observations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["requested_path"].as_str().unwrap())
        .collect();
    assert_eq!(order, [text(&alpha), text(&zed)]);
}

#[cfg(unix)]
#[test]
fn resolving_never_runs_the_executable() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    executable(
        dir.path(),
        "bin/node",
        &format!("#!/bin/sh\ntouch {}\n", marker.display()),
    );
    run(json!({
        "launches": [spec("node", dir.path())],
        "environment": env(&[("PATH", text(&dir.path().join("bin")))]),
    }));

    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn environment_values_never_appear_in_the_reply() {
    let dir = tempfile::tempdir().unwrap();
    executable(dir.path(), "bin/node", "binary\n");
    let result = run(json!({
        "launches": [spec("node", dir.path())],
        "environment": env(&[
            ("PATH", text(&dir.path().join("bin"))),
            ("API_TOKEN", "sk-test-not-a-real-secret"),
        ]),
    }));

    assert!(!result.to_string().contains("sk-test-not-a-real-secret"));
}

#[test]
fn launch_requests_are_validated_and_bounded() {
    let root = Path::new("/");
    assert_eq!(
        run_error(json!({"launches": [spec("node", Path::new("relative/dir"))]})),
        "runtime_identity_probe_launch_invalid"
    );
    let missing_dir = json!({"launches": [{"command": "node"}]}).to_string();
    assert_eq!(
        run_command(missing_dir.as_bytes()).unwrap_err(),
        "runtime_identity_probe_request_invalid"
    );
    assert_eq!(
        run_error(json!({"launches": [spec("no\u{0}de", root)]})),
        "runtime_identity_probe_launch_invalid"
    );
    assert_eq!(
        run_error(json!({"launches": [], "candidate_limit": 0})),
        "runtime_identity_probe_launch_invalid"
    );
    assert_eq!(
        run_error(json!({"launches": [], "candidate_limit": 129})),
        "runtime_identity_probe_launch_invalid"
    );
    assert_eq!(
        run_error(json!({"environment": {"A": "b\u{0}c"}})),
        "runtime_identity_probe_launch_invalid"
    );
    let many: Vec<Value> = (0..=super::MAX_LAUNCHES)
        .map(|_| spec("node", root))
        .collect();
    assert_eq!(
        run_error(json!({"launches": many})),
        "runtime_identity_probe_too_many_launches"
    );
}

#[test]
fn explicit_paths_alone_still_work_and_carry_empty_launch_fields() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("node");
    fs::write(&file, b"payload").unwrap();
    let result = run(json!({"paths": [text(&file)]}));

    assert_eq!(result["launches"], json!([]));
    assert_eq!(result["candidate_limit_reached"], false);
    assert_eq!(result["observations"].as_array().unwrap().len(), 1);
}

#[test]
fn normalize_drops_dot_components_and_keeps_parent_references() {
    assert_eq!(normalize(Path::new("/a/./b//c")), PathBuf::from("/a/b/c"));
    assert_eq!(normalize(Path::new("/a/../b")), PathBuf::from("/a/../b"));
}
