#![cfg(unix)]

use super::request::{cleanup_stale_requests, REQUEST_DIRECTORY_PREFIX, REQUEST_FILE_NAME};
use super::{native_shape, route_on, HookDirectDefer, Host, SinkTarget, WORKSPACE_PROFILE};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Recorded from the Python containment router on darwin, linux and win32.
const VECTORS: &str =
    include_str!("../../../../tests/fixtures/direct_contained_route/parity_vectors.json");

fn scratch(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "hook-direct-contained-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("tmp")).unwrap();
    fs::create_dir_all(root.join("work space")).unwrap();
    fs::canonicalize(root).unwrap()
}

fn launcher() -> String {
    std::env::current_exe()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

fn platform(name: &str) -> fn(&str) -> bool {
    match name {
        "darwin" => |_| true,
        "linux" => |profile| profile == WORKSPACE_PROFILE,
        _ => |_| false,
    }
}

/// A host whose every routed call keeps the daemon's sink.
fn daemon_sink(platform: fn(&str) -> bool) -> Host {
    Host {
        platform,
        native: |_, _, _| None,
    }
}

fn requests(temp: &Path) -> Vec<PathBuf> {
    fs::read_dir(temp)
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(REQUEST_DIRECTORY_PREFIX))
        })
        .map(|entry| entry.path())
        .collect()
}

#[test]
fn routes_every_vector_as_the_python_router_did() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let root = scratch("vectors");
    let temp = root.join("tmp");
    let workspace = root.join("work space").to_str().unwrap().to_owned();
    let command = vec![
        launcher(),
        "-I".to_owned(),
        "-c".to_owned(),
        "import sys; sys.path.insert(0, '/opt/guard src')".to_owned(),
    ];
    let target = SinkTarget {
        command: &command,
        harness: "claude-code",
        guard_home: "/guard home/.hol-guard",
        home_dir: "/home dir",
        workspace: &workspace,
    };
    let cases = vectors["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 129);
    for case in cases {
        let name = format!("{} on {}", case["name"], case["platform"]);
        let routed = route_on(
            &case["response"],
            case["payload"].as_object().unwrap(),
            &target,
            daemon_sink(platform(case["platform"].as_str().unwrap())),
            &temp,
        )
        .unwrap();
        let written = requests(&temp);
        if case["routed"] != json!(true) {
            assert!(routed.is_none(), "{name}");
            assert!(written.is_empty(), "{name}");
            continue;
        }
        let (routed, snapshot) = routed.unwrap_or_else(|| panic!("{name} was not routed"));
        assert_eq!(written.len(), 1, "{name}");
        let directory = &written[0];
        let request = directory.join(REQUEST_FILE_NAME);
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o7777,
            0o700
        );
        let metadata = fs::symlink_metadata(&request).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let raw = fs::read(&request).unwrap();
        let digest = hex::encode(Sha256::digest(&raw));
        let substitute = |value: &str| match value {
            "<workspace>" => workspace.clone(),
            "<request>" => request.to_str().unwrap().to_owned(),
            "<sha256>" => digest.clone(),
            "<guard_home>" => target.guard_home.to_owned(),
            "<home>" => target.home_dir.to_owned(),
            other => other.to_owned(),
        };
        let mut expected = command.clone();
        expected.extend(
            case["args"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| substitute(value.as_str().unwrap())),
        );
        let mut updated = case["updated_input"].as_object().unwrap().clone();
        updated.insert(
            "command".to_owned(),
            json!(crate::mcp_proxy_shlex::join(&expected)),
        );
        assert_eq!(
            routed,
            json!({
                "policy_action": "allow",
                "reason_code": "native_contained_execution_routed",
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "updatedInput": updated,
                },
            }),
            "{name}"
        );
        let mut snapshot_payload = case["snapshot_payload"].clone();
        snapshot_payload["cwd"] = json!(workspace);
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).unwrap(),
            json!({
                "schema": case["snapshot_schema"],
                "workspace": workspace,
                "payload": snapshot_payload,
            }),
            "{name}"
        );
        // An answer that defers after routing drops its snapshot.
        drop(snapshot);
        assert!(!directory.exists(), "{name}");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn the_sink_command_quotes_as_python_shlex_join() {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    for vector in vectors["shlex_join"].as_array().unwrap() {
        let tokens: Vec<String> = serde_json::from_value(vector["tokens"].clone()).unwrap();
        assert_eq!(
            crate::mcp_proxy_shlex::join(&tokens),
            vector["joined"].as_str().unwrap()
        );
    }
}

fn workspace_denial() -> Value {
    json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": "native_workspace_containment_required",
        "required_execution_profile": WORKSPACE_PROFILE,
    })
}

fn shell_payload(command: &str) -> Map<String, Value> {
    serde_json::from_value(json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": { "command": command },
    }))
    .unwrap()
}

fn route_shell(
    target: &SinkTarget<'_>,
    temp: &Path,
    command: &str,
) -> Result<Option<Value>, HookDirectDefer> {
    route_shell_on(target, temp, command, daemon_sink(platform("linux")))
}

fn route_shell_on(
    target: &SinkTarget<'_>,
    temp: &Path,
    command: &str,
    host: Host,
) -> Result<Option<Value>, HookDirectDefer> {
    route_on(
        &workspace_denial(),
        &shell_payload(command),
        target,
        host,
        temp,
    )
    .map(|routed| routed.map(|(response, _)| response))
}

#[test]
fn a_native_sink_runs_the_snapshot_through_the_runtime_itself() {
    let root = scratch("native");
    let temp = root.join("tmp");
    let workspace = root.join("work space").to_str().unwrap().to_owned();
    // The daemon's launcher may be gone: the native sink does not need it.
    let missing = vec![root.join("gone").to_str().unwrap().to_owned()];
    let target = SinkTarget {
        command: &missing,
        harness: "claude-code",
        guard_home: "/g",
        home_dir: "/h",
        workspace: &workspace,
    };
    let host = Host {
        platform: platform("darwin"),
        native: |_, _, _| Some("/opt/guard/guard-runtime".to_owned()),
    };
    let routed = route_shell_on(&target, &temp, "pytest -q", host)
        .unwrap()
        .unwrap();
    let sink = routed["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert!(
        sink.starts_with("/opt/guard/guard-runtime contained-workspace-sink --harness claude-code --guard-home /g --workspace "),
        "{sink}"
    );
    assert!(sink.ends_with(" --home /h"), "{sink}");
    let request_file = format!(" --request-file {}/", temp.display());
    assert!(sink.contains(&request_file), "{sink}");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn only_plain_workspace_runs_take_the_native_sink() {
    let root = scratch("shape");
    let workspace = root.join("work space");
    fs::create_dir_all(workspace.join("sub")).unwrap();
    fs::write(workspace.join("file"), "").unwrap();
    let workspace = workspace.to_str().unwrap();
    let denial = workspace_denial();
    let input = |command: &str| {
        shell_payload(command)["tool_input"]
            .as_object()
            .unwrap()
            .clone()
    };
    let shape = |command: &str| native_shape(&denial, &input(command), workspace);
    assert!(shape("pytest -q tests"));
    assert!(shape("npm test && cargo fmt --check"));
    // A `cd` into the workspace runs whole from its root on either sink.
    assert!(shape("cd sub && pytest"));
    assert!(shape("\tcd  sub/.  &&  pytest -q"));
    // Output filters, stderr folding and status reads run whole in the
    // sandbox, with the shell's own meaning.
    assert!(shape("pytest | tee log"));
    assert!(shape("pytest 2>&1"));
    assert!(shape("pytest; echo $?"));
    assert!(shape("npm run build 2>&1 | tail -20"));
    assert!(shape(
        "cd sub && pytest -q 2>&1 | head -40; echo \"EXIT:$?\""
    ));
    // A package directory inside the workspace runs whole from its root too.
    assert!(shape("npm --prefix sub test"));
    assert!(shape("bun --cwd sub run build 2>&1 | tail -5"));
    assert!(shape("pnpm --dir=sub/. run lint"));
    assert!(shape("pnpm -C sub run build"));
    assert!(shape("npm -C sub test 2>&1 | tail -20"));
    let inner = format!(
        "cd {}/sub && pytest",
        root.join("tmp/../work space").display()
    );
    assert!(
        !shape(&inner),
        "a space in the target is not one plain word"
    );
    for command in [
        "ls ~/work",
        "npm --prefix web test",
        // Like `cd`, a package directory at the root, out of it, after a
        // `cd`, or spelled any other way keeps the daemon's sink.
        "npm --prefix . test",
        "bun --cwd .. run build",
        "bun --cwd sub/.. run build",
        "bun --cwd file run build",
        "bun --cwd run build",
        "npm --prefix -w sub test",
        "cd sub && bun --cwd sub run build",
        "npm --prefix sub test && bun --cwd ../x run y",
        "pnpm --directory sub run lint",
        "npm --prefix 'sub' test",
        "git -C sub status",
        // Only npm and pnpm take the short flag natively, and only as its
        // own word.
        "make -C sub test",
        "pnpm -Csub run build",
        "pnpm -C . run build",
        "pnpm -C sub run build && git -C sub status",
        "pytest -C sub",
        // The daemon plans a `cd` to the root, or out of it, again there.
        "cd . && pytest",
        "cd sub/.. && pytest",
        "cd .. && pytest",
        "cd /tmp && pytest",
        // Only `&&` after one plain, existing directory.
        "cd sub; pytest",
        "cd sub&& pytest",
        "cd sub &&",
        "cd sub",
        "cd 'sub' && pytest",
        "cd $HOME && pytest",
        "cd missing && pytest",
        "cd file && pytest",
        "\ncd sub && pytest",
        "cdk deploy",
    ] {
        assert!(!shape(command), "{command}");
    }
    let mut moved = input("pytest");
    moved.insert("cwd".to_owned(), json!("/elsewhere"));
    assert!(!native_shape(&denial, &moved, workspace));
    let mut publish = denial.clone();
    publish["reason"] = json!(crate::contained_workspace_sink::PUBLISH_REASON);
    assert!(!native_shape(
        &publish,
        &input("pytest && git push"),
        workspace
    ));
    let mut other = denial.clone();
    other["reason_code"] = json!("native_test_containment_required");
    assert!(!native_shape(&other, &input("pytest"), workspace));
    // An outside-roots review a local CLI grant may route stays with the
    // daemon, which asks the store and re-asks it in the sink; the direct lane
    // never answers it on a grant of its own.
    let outside = json!({
        "decision": "deny",
        "policy_action": "review",
        "minimum_action": "review",
        "reason_code": "native_workspace_containment_executable_outside_roots",
    });
    assert!(!native_shape(&outside, &input("lanectl status"), workspace));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_launcher_removed_since_the_publish_defers_and_an_oversized_call_stays_denied() {
    let root = scratch("limits");
    let temp = root.join("tmp");
    let workspace = root.join("work space").to_str().unwrap().to_owned();
    let missing = vec![root.join("gone").to_str().unwrap().to_owned()];
    let mut target = SinkTarget {
        command: &missing,
        harness: "claude-code",
        guard_home: "/g",
        home_dir: "/h",
        workspace: &workspace,
    };
    assert_eq!(
        route_shell(&target, &temp, "pytest"),
        Err(HookDirectDefer::ContainedRouteFailed)
    );
    let present = vec![launcher()];
    target.command = &present;
    let oversized = "x".repeat(1_100_000);
    assert_eq!(route_shell(&target, &temp, &oversized), Ok(None));
    assert!(requests(&temp).is_empty());
    let gone_workspace = root.join("no workspace").to_str().unwrap().to_owned();
    target.workspace = &gone_workspace;
    assert_eq!(
        route_shell(&target, &temp, "pytest"),
        Err(HookDirectDefer::ContainedRouteFailed)
    );
    assert!(requests(&temp).is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_zcode_call_runs_the_sink_under_its_own_harness() {
    let root = scratch("zcode");
    let temp = root.join("tmp");
    let workspace = root.join("work space").to_str().unwrap().to_owned();
    let command = vec![launcher()];
    let target = SinkTarget {
        command: &command,
        harness: "zcode",
        guard_home: "/g",
        home_dir: "/h",
        workspace: &workspace,
    };
    let routed = route_shell(&target, &temp, "pytest").unwrap().unwrap();
    let sink = routed["hookSpecificOutput"]["updatedInput"]["command"]
        .as_str()
        .unwrap();
    assert!(sink.contains(" --harness zcode --guard-home /g "), "{sink}");
    assert!(sink.ends_with(" --home /h"), "{sink}");
    fs::remove_dir_all(root).unwrap();
}

fn request_directory(temp: &Path, name: &str, file_mode: u32, age: Duration) -> PathBuf {
    let directory = temp.join(format!("{REQUEST_DIRECTORY_PREFIX}{name}"));
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let request = directory.join(REQUEST_FILE_NAME);
    fs::write(&request, b"{}").unwrap();
    fs::set_permissions(&request, fs::Permissions::from_mode(file_mode)).unwrap();
    let then = SystemTime::now() - age;
    fs::File::options()
        .write(true)
        .open(&request)
        .unwrap()
        .set_modified(then)
        .unwrap();
    fs::File::open(&directory)
        .unwrap()
        .set_modified(then)
        .unwrap();
    directory
}

#[test]
fn only_private_requests_older_than_a_day_are_reclaimed() {
    let root = scratch("cleanup");
    let temp = root.join("tmp");
    let day = Duration::from_secs(86_400);
    let stale = request_directory(&temp, "stale", 0o600, day * 2);
    let fresh = request_directory(&temp, "fresh", 0o600, Duration::from_secs(60));
    let shared = request_directory(&temp, "shared", 0o644, day * 2);
    let elsewhere = root.join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let linked = temp.join(format!("{REQUEST_DIRECTORY_PREFIX}linked"));
    std::os::unix::fs::symlink(&elsewhere, &linked).unwrap();
    cleanup_stale_requests(&temp);
    assert!(!stale.exists());
    assert!(fresh.join(REQUEST_FILE_NAME).exists());
    assert!(shared.join(REQUEST_FILE_NAME).exists());
    assert!(fs::symlink_metadata(&linked).is_ok() && elsewhere.is_dir());
    fs::remove_dir_all(root).unwrap();
}
