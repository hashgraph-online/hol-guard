use std::os::unix::fs::PermissionsExt;

use sha2::{Digest, Sha256};

use super::plan_check::linked_git;
use super::snapshot::decode_request;
use super::*;
use crate::hook_direct::contained::request::{
    REQUEST_DIRECTORY_PREFIX, REQUEST_FILE_NAME, REQUEST_SCHEMA,
};

fn fresh_workspace() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let workspace = std::fs::canonicalize(root.path()).unwrap();
    (root, workspace)
}

fn request(workspace: &Path, payload: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": REQUEST_SCHEMA,
        "workspace": workspace,
        "payload": payload,
    }))
    .unwrap()
}

fn call(workspace: &Path, command: &str) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_input": { "command": command },
        "cwd": workspace,
    })
}

fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

/// Write `raw` as a snapshot under `temp` with the given modes.
fn snapshot(temp: &Path, raw: &[u8], directory_mode: u32, file_mode: u32) -> PathBuf {
    let directory = temp.join(format!("{REQUEST_DIRECTORY_PREFIX}test"));
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join(REQUEST_FILE_NAME);
    std::fs::write(&file, raw).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(file_mode)).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(directory_mode)).unwrap();
    file
}

#[test]
fn arguments_are_exactly_the_six_the_route_writes() {
    let args: Vec<String> = [
        "--harness",
        "claude-code",
        "--guard-home",
        "/g",
        "--workspace",
        "/w",
        "--request-file",
        "/t/r.json",
        "--request-sha256",
        "ab",
        "--home",
        "/h",
    ]
    .map(str::to_owned)
    .to_vec();
    let parsed = Arguments::parse(&args).unwrap();
    assert_eq!(parsed.harness, "claude-code");
    assert_eq!(parsed.home, PathBuf::from("/h"));
    assert!(Arguments::parse(&args[..11]).is_none());
    let mut repeated = args.clone();
    repeated[10] = "--harness".to_owned();
    assert!(Arguments::parse(&repeated).is_none());
    let mut unknown = args;
    unknown[0] = "harness".to_owned();
    assert!(Arguments::parse(&unknown).is_none());
}

#[test]
fn a_snapshot_is_read_once_and_only_when_private() {
    let (_root, workspace) = fresh_workspace();
    let temp = tempfile::tempdir().unwrap();
    let raw = request(&workspace, call(&workspace, "pytest"));
    let file = snapshot(temp.path(), &raw, 0o700, 0o600);
    assert_eq!(
        read_request(&file, &"0".repeat(64), &workspace),
        Err(Failure::unauthorized())
    );
    let payload = read_request(&file, &digest(&raw), &workspace).unwrap();
    assert_eq!(payload["tool_input"]["command"], json!("pytest"));
    assert!(!file.exists());
    assert!(!file.parent().unwrap().exists());

    let shared = snapshot(temp.path(), &raw, 0o755, 0o600);
    assert!(read_request(&shared, &digest(&raw), &workspace).is_err());
    std::fs::remove_dir_all(shared.parent().unwrap()).unwrap();
    let readable = snapshot(temp.path(), &raw, 0o700, 0o644);
    assert!(read_request(&readable, &digest(&raw), &workspace).is_err());
    assert!(readable.exists());
}

#[test]
fn a_snapshot_must_name_this_workspace_and_a_shell_call() {
    let (_root, workspace) = fresh_workspace();
    let (_other_root, other) = fresh_workspace();
    let check = |raw: &[u8]| decode_request(raw, &digest(raw), &workspace).is_some();
    assert!(check(&request(&workspace, call(&workspace, "pytest"))));
    assert!(!check(&request(&other, call(&workspace, "pytest"))));
    assert!(!check(&request(&workspace, call(&other, "pytest"))));
    let mut edit = call(&workspace, "pytest");
    edit["tool_name"] = json!("Bash");
    assert!(!check(&request(&workspace, edit)));
    let mut post = call(&workspace, "pytest");
    post["hook_event_name"] = json!("PostToolUse");
    assert!(!check(&request(&workspace, post)));
    let mut extra: Value =
        serde_json::from_slice(&request(&workspace, call(&workspace, "x"))).unwrap();
    extra["more"] = json!(1);
    assert!(!check(&serde_json::to_vec(&extra).unwrap()));
    let duplicated = format!(
        "{{\"schema\":\"{REQUEST_SCHEMA}\",\"schema\":\"{REQUEST_SCHEMA}\",\"workspace\":{},\"payload\":{}}}",
        json!(workspace),
        call(&workspace, "pytest")
    );
    assert!(!check(duplicated.as_bytes()));
}

fn receipt() -> Map<String, Value> {
    json!({
        "decision": "deny",
        "policy_action": "sandbox-required",
        "reason_code": WORKSPACE_REASON,
        "required_execution_profile": WORKSPACE_PROFILE,
        "command_binding_digest": "d",
    })
    .as_object()
    .unwrap()
    .clone()
}

#[test]
fn only_a_live_workspace_requirement_is_a_receipt() {
    assert!(receipt_matches(&receipt()));
    for (name, value) in [
        ("decision", json!("allow")),
        ("policy_action", json!("block")),
        ("reason_code", json!("other")),
        ("required_execution_profile", json!("test-contained-v1")),
        ("observe_mode", json!(true)),
        ("command_binding_digest", json!(1)),
    ] {
        let mut changed = receipt();
        changed.insert(name.to_owned(), value);
        assert!(!receipt_matches(&changed), "{name}");
    }
}

#[cfg(target_os = "macos")]
fn plan(workspace: &str, command: &str) -> Map<String, Value> {
    json!({
        "profile_version": WORKSPACE_PROFILE,
        "backend": "macos-seatbelt",
        "backend_executable": "/usr/bin/sandbox-exec",
        "workspace": workspace,
        "cwd": workspace,
        "executable": "/bin/sh",
        "command": ["/bin/sh", "-c", command],
        "command_sha256": digest(command.as_bytes()),
        "allowed_executables": [],
        "read_only_roots": [],
        "exec_roots": ["/usr/bin"],
        "write_denials": [],
        "linked_git": null,
        "sandbox_path": "/usr/bin:/bin",
        "bootstrap_git": null,
        "prefix_command": null,
        "native_suffix": null,
        "denied_capabilities": [],
    })
    .as_object()
    .unwrap()
    .clone()
}

#[cfg(target_os = "macos")]
fn validate(plan: Map<String, Value>, command: &str) -> Result<(), String> {
    validated_plan(Value::Object(plan), command, "/w")
        .map(|_| ())
        .map_err(|failure| failure.message)
}

#[cfg(target_os = "macos")]
#[test]
fn a_plan_must_run_exactly_the_authorized_command() {
    assert_eq!(validate(plan("/w", "pytest"), "pytest"), Ok(()));
    assert_eq!(validate(plan("/w/", "pytest"), "pytest"), Ok(()));
    let mismatch = Err(PLAN_MISMATCH.to_owned());
    assert_eq!(validate(plan("/w", "pytest -x"), "pytest"), mismatch);
    assert_eq!(validate(plan("/other", "pytest"), "pytest"), mismatch);
    let mut digest_changed = plan("/w", "pytest");
    digest_changed["command_sha256"] = json!(digest(b"other"));
    assert_eq!(validate(digest_changed, "pytest"), mismatch);
    let mut suffix = plan("/w", "pytest");
    suffix["native_suffix"] = json!("git push");
    assert_eq!(validate(suffix, "pytest"), mismatch);
    let mut allowed = plan("/w", "pytest");
    allowed["allowed_executables"] = json!(["/usr/bin/python3"]);
    assert_eq!(validate(allowed, "pytest"), mismatch);
    let mut missing = plan("/w", "pytest");
    missing.remove("denied_capabilities");
    assert_eq!(validate(missing, "pytest"), Err(INVALID_PLAN.to_owned()));
    let mut profile = plan("/w", "pytest");
    profile["profile_version"] = json!("test-contained-v1");
    assert_eq!(validate(profile, "pytest"), Err(INVALID_PLAN.to_owned()));
}

#[cfg(target_os = "macos")]
#[test]
fn a_bootstrapped_plan_runs_the_rest_after_git_init() {
    let command = "npm ci && git init && pytest";
    let mut bootstrapped = plan("/w", "pytest");
    bootstrapped["bootstrap_git"] = json!([]);
    bootstrapped["prefix_command"] = json!("npm ci");
    let accepted = validated_plan(Value::Object(bootstrapped.clone()), command, "/w").unwrap();
    assert_eq!(accepted.prefix.as_deref(), Some("npm ci"));
    assert_eq!(accepted.bootstrap, Some(json!([])));
    // A prefix only ever comes with a bootstrap, and must lead the command.
    let mut foreign = bootstrapped.clone();
    foreign["prefix_command"] = json!("curl x");
    assert_eq!(validate(foreign, command), Err(PLAN_MISMATCH.to_owned()));
    let mut unbootstrapped = bootstrapped;
    unbootstrapped["bootstrap_git"] = Value::Null;
    assert_eq!(
        validate(unbootstrapped, command),
        Err(PLAN_MISMATCH.to_owned())
    );
}

#[test]
fn a_linked_worktree_names_both_absolute_git_directories() {
    assert!(linked_git(
        &json!({"common": "/r/.git", "admin": "/r/.git/worktrees/w"})
    ));
    assert!(!linked_git(&json!({"common": "r/.git", "admin": "/a"})));
    assert!(!linked_git(&json!({"common": "/r/.git"})));
    assert!(!linked_git(
        &json!({"common": "/c", "admin": "/a", "more": "/m"})
    ));
}

#[test]
fn an_operation_reply_is_a_value_or_a_named_failure() {
    assert_eq!(envelope(json!({"value": 3})), Ok(json!(3)));
    assert_eq!(
        envelope(json!({"reason_code": INVALID_COMMAND, "message": "no"})),
        Err(Failure::new(INVALID_COMMAND, "no"))
    );
    let unavailable = Err(unavailable("invalid_reply"));
    assert_eq!(
        envelope(json!({"reason_code": "made_up", "message": "no"})),
        unavailable
    );
    assert_eq!(envelope(json!({"value": 3, "extra": 1})), unavailable);
    assert_eq!(
        envelope(json!({"reason_code": INVALID_COMMAND, "message": "x".repeat(4097)})),
        unavailable
    );
    assert_eq!(envelope(json!([1])), unavailable);
}

#[test]
fn paths_normalise_as_pathlib_does() {
    assert_eq!(py_normal("/a//b/./c/"), "/a/b/c");
    assert_eq!(py_normal("//a/b"), "//a/b");
    assert_eq!(py_normal("///a"), "/a");
    assert_eq!(py_normal("a/.."), "a/..");
    assert_eq!(py_normal(""), ".");
    assert_eq!(py_normal("./"), ".");
}

#[test]
fn private_scratch_lives_exactly_as_long_as_its_owner() {
    let root = PrivateRoot::create().unwrap();
    let path = root.path.clone();
    assert_eq!(std::fs::canonicalize(&path).unwrap(), path);
    for name in ["", "home", "tmp"] {
        let mode = std::fs::metadata(path.join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "{name}");
    }
    drop(root);
    assert!(!path.exists());
}

#[test]
fn private_home_holds_only_a_plain_safety_guide() {
    let seeded = |prepare: &dyn Fn(&Path)| {
        let (_home_root, home) = fresh_workspace();
        let (_private_root, private) = fresh_workspace();
        prepare(&home);
        super::runner::seed_safety_guide(&home, &private);
        std::fs::read(private.join(".hol-support/SAFETY.md")).ok()
    };
    let guide = |home: &Path| {
        std::fs::create_dir(home.join(".hol-support")).unwrap();
        std::fs::write(home.join(".hol-support/SAFETY.md"), b"guide").unwrap();
    };
    assert_eq!(seeded(&guide).as_deref(), Some(&b"guide"[..]));
    let copied = {
        let (_home_root, home) = fresh_workspace();
        let (_private_root, private) = fresh_workspace();
        guide(&home);
        super::runner::seed_safety_guide(&home, &private);
        std::fs::metadata(private.join(".hol-support/SAFETY.md"))
            .unwrap()
            .permissions()
            .mode()
    };
    assert_eq!(copied & 0o777, 0o600);
    // Nothing to copy, or a guide swapped for a link to another file.
    let refused: [&dyn Fn(&Path); 5] = [
        &|_| {},
        &|home| {
            std::fs::create_dir(home.join(".hol-support")).unwrap();
            std::fs::write(home.join("id_rsa"), b"key").unwrap();
            std::os::unix::fs::symlink(home.join("id_rsa"), home.join(".hol-support/SAFETY.md"))
                .unwrap();
        },
        &|home| {
            std::fs::create_dir(home.join(".hol-support")).unwrap();
            std::fs::write(home.join("id_rsa"), b"key").unwrap();
            std::fs::hard_link(home.join("id_rsa"), home.join(".hol-support/SAFETY.md")).unwrap();
        },
        &|home| {
            std::fs::create_dir(home.join(".ssh")).unwrap();
            std::fs::write(home.join(".ssh/SAFETY.md"), b"key").unwrap();
            std::os::unix::fs::symlink(home.join(".ssh"), home.join(".hol-support")).unwrap();
        },
        &|home| {
            std::fs::create_dir_all(home.join(".hol-support/SAFETY.md")).unwrap();
        },
    ];
    for prepare in refused {
        assert_eq!(seeded(prepare), None);
    }
    let oversized = |home: &Path| {
        std::fs::create_dir(home.join(".hol-support")).unwrap();
        std::fs::write(
            home.join(".hol-support/SAFETY.md"),
            vec![b'x'; 64 * 1024 + 1],
        )
        .unwrap();
    };
    assert_eq!(seeded(&oversized), None);
}
