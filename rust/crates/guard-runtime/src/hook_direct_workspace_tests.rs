//! Workspace vectors whose expected values are the daemon's. The Python side
//! of the same vectors is pinned by
//! `tests/test_hook_workspace_temporary_fallthrough.py`.

use super::super::HookDirectDefer;
use super::{normalized_workspace, workspace_candidate};
use serde_json::{json, Map, Value};
use std::path::PathBuf;

const HOME: &str = "/home/guard";

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn normalized(value: &str) -> Result<Option<String>, HookDirectDefer> {
    normalized_workspace(Some(value), HOME)
}

/// A directory under `/tmp`, with `sub/`, a link `to-tmp -> /tmp` and a link
/// `sub/up -> ../..`, removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let root = PathBuf::from(format!("/tmp/hdw-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::os::unix::fs::symlink("/tmp", root.join("to-tmp")).unwrap();
        std::os::unix::fs::symlink("../..", root.join("sub/up")).unwrap();
        Self(root)
    }

    fn path(&self, rest: &str) -> String {
        let root = self.0.to_str().unwrap();
        if rest.is_empty() {
            root.to_owned()
        } else {
            format!("{root}/{rest}")
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn temporary_roots_are_skipped_like_the_daemon() {
    for root in ["/tmp", "/var/tmp", "/tmp/None", "/tmp/x/..", " /tmp/ "] {
        assert_eq!(normalized(root), Ok(None), "{root:?}");
    }
    let scratch = Scratch::new("skip");
    // Links that resolve back to a temporary root are skipped as that root.
    for link in ["to-tmp", "sub/up"] {
        assert_eq!(normalized(&scratch.path(link)), Ok(None), "{link:?}");
    }
    // A directory below a temporary root, or a missing one, is kept.
    for kept in [
        scratch.path(""),
        scratch.path("sub"),
        scratch.path("missing"),
        "/work/repo".to_owned(),
    ] {
        assert_eq!(normalized(&kept), Ok(Some(kept.clone())), "{kept:?}");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn darwin_temporary_roots_are_skipped_like_the_daemon() {
    assert_eq!(normalized("/private/tmp"), Ok(None));
    assert_eq!(normalized("/private/var/tmp"), Ok(None));
    // The per-user root needs its exact `T` and a two-character bucket.
    assert_eq!(
        normalized("/var/folders/abc/id/T"),
        Ok(Some("/var/folders/abc/id/T".to_owned()))
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn darwin_only_roots_are_kept_elsewhere() {
    assert_eq!(
        normalized("/private/tmp"),
        Ok(Some("/private/tmp".to_owned()))
    );
}

#[test]
fn own_temporary_directory_is_never_taken_as_a_workspace() {
    // The daemon skips its `gettempdir()`. Where only this process's
    // temporary directory would decide that, the hook defers instead.
    let own = std::env::temp_dir();
    let verdict = normalized(own.to_str().unwrap());
    assert!(
        matches!(verdict, Ok(None) | Err(HookDirectDefer::WorkspaceInvalid)),
        "{verdict:?}"
    );
}

#[test]
fn unreproducible_paths_still_defer() {
    // Python raises on an embedded NUL rather than skipping the path.
    assert_eq!(
        normalized("/tmp/a\u{0}b"),
        Err(HookDirectDefer::WorkspaceInvalid)
    );
}

#[test]
fn skipped_cwd_falls_through_to_the_query() {
    let scratch = Scratch::new("fall");
    for cwd in ["/tmp".to_owned(), scratch.path("to-tmp")] {
        let payload = object(json!({ "tool_name": "read_file", "cwd": cwd }));
        assert_eq!(
            workspace_candidate(&payload, Some("/work/query"), HOME),
            Ok(Some("/work/query".to_owned())),
            "{cwd:?}"
        );
        // With every candidate skipped the daemon has no workspace.
        assert_eq!(workspace_candidate(&payload, None, HOME), Ok(None));
        assert_eq!(
            workspace_candidate(&payload, Some("/var/tmp"), HOME),
            Ok(None)
        );
    }
}

#[test]
fn temporary_workdir_still_rejects_the_workspace() {
    // The daemon rejects such a workdir and runs without a workspace; it does
    // not fall through to the `cwd`.
    let payload = object(json!({
        "tool_name": "exec_command",
        "tool_input": { "workdir": "/tmp" },
        "cwd": "/work/cwd",
    }));
    assert_eq!(
        workspace_candidate(&payload, Some("/work/query"), HOME),
        Err(HookDirectDefer::WorkspaceInvalid)
    );
    // A workdir keeps a trailing `None`; only `cwd` and the query drop it.
    let payload = object(json!({
        "tool_name": "exec_command",
        "tool_input": { "workdir": "/tmp/None" },
    }));
    assert_eq!(
        workspace_candidate(&payload, None, HOME),
        Ok(Some("/tmp/None".to_owned()))
    );
}
