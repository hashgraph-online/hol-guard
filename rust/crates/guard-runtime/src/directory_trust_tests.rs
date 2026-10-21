//! The directory rules the daemon used to apply in Python, checked against
//! real directories: a home it may reach, a Guard home kept elsewhere, and
//! the owned scratch directory a harness hands over as a workspace.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use super::{
    canonical_guard_home_path, evaluate_directory_trust_request, trusted_guard_directory_roots,
    validate_guard_directory_path, validated_hook_guard_home, validated_owned_temporary_workspace,
    DirectoryTrustRejection, DirectoryTrustRequestV1, DIRECTORY_TRUST_REQUEST_SCHEMA,
    DIRECTORY_TRUST_RESULT_SCHEMA,
};
use crate::guard_paths::python_realpath_lax;

fn canonical(path: &Path) -> PathBuf {
    python_realpath_lax(path).expect("an existing absolute path resolves")
}

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// A home with a Guard home inside it, which is the ordinary install.
struct Install {
    home: TempDir,
}

impl Install {
    fn new() -> Self {
        let home = TempDir::new().expect("a temporary home");
        std::fs::create_dir(home.path().join(".hol-guard")).expect("a guard home");
        Self { home }
    }

    fn home_dir(&self) -> String {
        text(self.home.path())
    }

    fn guard_home(&self) -> String {
        text(&self.home.path().join(".hol-guard"))
    }

    fn roots(&self) -> Vec<PathBuf> {
        trusted_guard_directory_roots(&self.guard_home(), &self.home_dir()).expect("roots resolve")
    }

    fn validate(&self, value: &str) -> Result<PathBuf, DirectoryTrustRejection> {
        validate_guard_directory_path(
            value,
            &self.roots(),
            &self.home_dir(),
            &std::env::temp_dir(),
            false,
        )
    }
}

#[test]
fn a_home_with_its_guard_home_inside_has_one_root() {
    let install = Install::new();
    assert_eq!(install.roots(), vec![canonical(install.home.path())]);
}

#[test]
fn the_home_itself_is_a_directory_the_caller_may_name() {
    let install = Install::new();
    assert_eq!(
        install.validate(&install.home_dir()),
        Ok(canonical(install.home.path()))
    );
}

#[test]
fn a_directory_under_the_home_is_a_directory_the_caller_may_name() {
    let install = Install::new();
    let project = install.home.path().join("projects/app");
    std::fs::create_dir_all(&project).expect("a project directory");
    assert_eq!(install.validate(&text(&project)), Ok(canonical(&project)));
}

#[test]
fn a_tilde_path_is_expanded_against_the_callers_home() {
    let install = Install::new();
    assert_eq!(
        install.validate("~/.hol-guard"),
        Ok(canonical(&install.home.path().join(".hol-guard")))
    );
}

#[test]
fn a_relative_path_never_names_a_directory() {
    let install = Install::new();
    assert_eq!(
        install.validate("projects/app"),
        Err(DirectoryTrustRejection::RelativePath)
    );
}

#[test]
fn another_users_home_is_not_resolved_on_their_behalf() {
    let install = Install::new();
    assert_eq!(
        install.validate("~someone-else/projects"),
        Err(DirectoryTrustRejection::PathResolveFailed)
    );
}

#[test]
fn a_path_outside_every_root_is_refused() {
    let install = Install::new();
    assert_eq!(
        install.validate("/usr/lib"),
        Err(DirectoryTrustRejection::UnexpectedRoot)
    );
}

#[test]
fn a_guard_home_kept_outside_the_home_opens_its_own_root() {
    let install = Install::new();
    let elsewhere = TempDir::new().expect("a directory outside the home");
    let guard_home = text(&elsewhere.path().join("guard"));
    std::fs::create_dir(&guard_home).expect("a guard home");
    let sibling = elsewhere.path().join("sibling");
    std::fs::create_dir(&sibling).expect("a sibling directory");

    let roots = trusted_guard_directory_roots(&guard_home, &install.home_dir()).expect("roots");
    assert_eq!(
        roots,
        vec![canonical(install.home.path()), canonical(elsewhere.path())]
    );
    assert_eq!(
        validate_guard_directory_path(
            &text(&sibling),
            &roots,
            &install.home_dir(),
            &std::env::temp_dir(),
            false,
        ),
        Ok(canonical(&sibling))
    );
}

#[test]
fn a_guard_home_has_to_be_the_store_this_runtime_is_serving() {
    let install = Install::new();
    let elsewhere = TempDir::new().expect("another guard home");
    assert_eq!(
        validated_hook_guard_home(
            &install.guard_home(),
            &install.guard_home(),
            &install.home_dir()
        ),
        Ok(canonical(&install.home.path().join(".hol-guard")))
    );
    assert_eq!(
        validated_hook_guard_home(
            &text(elsewhere.path()),
            &install.guard_home(),
            &install.home_dir()
        ),
        Err(DirectoryTrustRejection::UnexpectedGuardHome)
    );
    assert_eq!(
        validated_hook_guard_home(".hol-guard", &install.guard_home(), &install.home_dir()),
        Err(DirectoryTrustRejection::RelativePath)
    );
}

#[test]
fn a_scratch_directory_the_caller_owns_is_a_workspace_and_nothing_else() {
    let install = Install::new();
    let scratch = TempDir::new().expect("a scratch directory");
    let temp_dir = std::env::temp_dir();
    let workspace = text(scratch.path());

    assert_eq!(
        validate_guard_directory_path(
            &workspace,
            &install.roots(),
            &install.home_dir(),
            &temp_dir,
            true,
        ),
        Ok(canonical(scratch.path()))
    );
    assert_eq!(
        validate_guard_directory_path(
            &workspace,
            &install.roots(),
            &install.home_dir(),
            &temp_dir,
            false,
        ),
        Err(DirectoryTrustRejection::UnexpectedRoot)
    );
}

#[test]
fn the_shared_temporary_root_is_not_itself_a_workspace() {
    let install = Install::new();
    let temp_dir = std::env::temp_dir();
    assert_eq!(
        validated_owned_temporary_workspace(&temp_dir, &install.home_dir(), &temp_dir),
        None
    );
}

#[test]
fn a_file_under_the_temporary_root_is_not_a_workspace() {
    let install = Install::new();
    let scratch = TempDir::new().expect("a scratch directory");
    let file = scratch.path().join("notes.txt");
    std::fs::write(&file, b"").expect("a file");
    assert_eq!(
        validated_owned_temporary_workspace(&file, &install.home_dir(), &std::env::temp_dir()),
        None
    );
}

#[test]
fn a_guard_home_that_does_not_exist_still_has_one_stable_key() {
    let home = TempDir::new().expect("a temporary home");
    let key = canonical_guard_home_path("~/.hol-guard", &text(home.path())).expect("a key");
    assert_eq!(
        PathBuf::from(&key),
        canonical(home.path()).join(".hol-guard")
    );
}

#[test]
fn every_rejection_keeps_the_spelling_the_daemons_counters_use() {
    assert_eq!(
        DirectoryTrustRejection::RelativePath.reason(),
        "relative_path"
    );
    assert_eq!(
        DirectoryTrustRejection::PathResolveFailed.reason(),
        "path_resolve_failed"
    );
    assert_eq!(
        DirectoryTrustRejection::UnexpectedRoot.reason(),
        "unexpected_root"
    );
    assert_eq!(
        DirectoryTrustRejection::UnexpectedGuardHome.reason(),
        "unexpected_guard_home"
    );
}

fn evaluate(request: Value) -> Value {
    let request: DirectoryTrustRequestV1 =
        serde_json::from_value(request).expect("the request parses");
    let body = evaluate_directory_trust_request(&request).expect("the operation answers");
    serde_json::from_slice(&body).expect("the answer is JSON")
}

#[test]
fn the_operation_settles_every_candidate_in_one_call() {
    let install = Install::new();
    let scratch = TempDir::new().expect("a scratch directory");
    let body = evaluate(json!({
        "schema": DIRECTORY_TRUST_REQUEST_SCHEMA,
        "request_id": "req-directory-trust",
        "guard_home": install.guard_home(),
        "home_dir": install.home_dir(),
        "temp_dir": text(&std::env::temp_dir()),
        "candidates": [
            {"parameter": "home", "value": install.home_dir()},
            {"parameter": "guard-home", "value": install.guard_home()},
            {"parameter": "workspace", "value": text(scratch.path())},
            {"parameter": "home", "value": "/usr/lib"},
        ],
    }));

    assert_eq!(body["schema"], DIRECTORY_TRUST_RESULT_SCHEMA);
    assert_eq!(body["request_id"], json!("req-directory-trust"));
    assert_eq!(body["status"], json!("ok"));
    assert!(
        body["request_sha256"]
            .as_str()
            .expect("a digest")
            .starts_with("sha256:"),
        "the answer binds the bytes the caller sent"
    );
    assert_eq!(
        body["canonical_guard_home"],
        json!(text(&canonical(&install.home.path().join(".hol-guard"))))
    );
    let results = body["results"].as_array().expect("results");
    assert_eq!(results.len(), 4);
    assert_eq!(results[0]["trusted"], json!(true));
    assert_eq!(
        results[1]["path"],
        json!(text(&canonical(&install.home.path().join(".hol-guard"))))
    );
    assert_eq!(results[2]["path"], json!(text(&canonical(scratch.path()))));
    assert_eq!(results[3]["trusted"], json!(false));
    assert_eq!(results[3]["reason"], json!("unexpected_root"));
    assert!(
        results[3].get("path").is_none(),
        "a rejection never carries the path"
    );
}

#[test]
fn a_rule_tells_two_spellings_of_the_same_workspace_apart() {
    let install = Install::new();
    let scratch = TempDir::new().expect("a scratch directory");
    let body = evaluate(json!({
        "schema": DIRECTORY_TRUST_REQUEST_SCHEMA,
        "request_id": "req-directory-trust",
        "guard_home": install.guard_home(),
        "home_dir": install.home_dir(),
        "temp_dir": text(&std::env::temp_dir()),
        "candidates": [
            {
                "parameter": "workspace-workdir",
                "rule": "exec-workdir",
                "value": "none",
            },
            {
                "parameter": "workspace-payload",
                "rule": "hook-workspace",
                "value": format!("{}/None", text(scratch.path())),
            },
            {
                "parameter": "workspace-query",
                "rule": "hook-workspace",
                "value": "   ",
            },
        ],
    }));

    let results = body["results"].as_array().expect("results");
    assert_eq!(results.len(), 3);
    // A sentinel names no directory, which is not a rejection: the route
    // falls through to the next spelling instead of refusing the request.
    assert_eq!(results[0]["parameter"], json!("workspace-workdir"));
    assert_eq!(results[0]["absent"], json!(true));
    assert!(results[0].get("reason").is_none());
    assert_eq!(results[1]["parameter"], json!("workspace-payload"));
    assert_eq!(results[1]["path"], json!(text(&canonical(scratch.path()))));
    assert_eq!(results[2]["absent"], json!(true));
}

#[test]
fn a_workspace_spelling_with_no_root_is_refused_as_the_relative_path_it_is() {
    // These rules read a spelling lexically, so a path naming no root says
    // nothing about which directory it means: reading it would mean reading
    // the daemon's own working directory. The caller is told that, not that
    // the path failed to resolve.
    let install = Install::new();
    let body = evaluate(json!({
        "schema": DIRECTORY_TRUST_REQUEST_SCHEMA,
        "request_id": "req-relative-hook-spellings",
        "guard_home": install.guard_home(),
        "home_dir": install.home_dir(),
        "temp_dir": text(&std::env::temp_dir()),
        "candidates": [
            {"parameter": "workspace-payload", "rule": "hook-workspace", "value": "project/src"},
            {"parameter": "workspace-query", "rule": "hook-workspace", "value": "project/None"},
            {"parameter": "exec-workdir", "rule": "exec-workdir", "value": "project/src"},
            {"parameter": "workspace-workdir", "rule": "exec-workdir", "value": "../sibling"},
        ],
    }));

    let results = body["results"]
        .as_array()
        .expect("one verdict per candidate");
    assert_eq!(results.len(), 4);
    for result in results {
        assert_eq!(result["trusted"], json!(false));
        assert_eq!(result["reason"], json!("relative_path"));
        assert!(result.get("path").is_none());
    }
}

#[test]
fn a_payload_reference_is_read_only_where_guards_writer_put_it() {
    let install = Install::new();
    let holder = TempDir::new().expect("a temporary holder");
    let directory = holder.path().join("hol-guard-hook-payload-abc123");
    std::fs::create_dir(&directory).expect("a payload directory");
    let payload = directory.join("payload.json");
    std::fs::write(&payload, b"{}").expect("a payload file");
    let stray = holder.path().join("payload.json");
    std::fs::write(&stray, b"{}").expect("a stray file");

    let body = evaluate(json!({
        "schema": DIRECTORY_TRUST_REQUEST_SCHEMA,
        "request_id": "req-directory-trust",
        "guard_home": install.guard_home(),
        "home_dir": install.home_dir(),
        "temp_dir": text(holder.path()),
        "candidates": [
            {"parameter": "payload-reference", "value": text(&payload)},
            {"parameter": "payload-reference", "value": text(&stray)},
        ],
    }));

    let results = body["results"].as_array().expect("results");
    assert_eq!(results[0]["path"], json!(text(&canonical(&payload))));
    assert_eq!(results[1]["trusted"], json!(false));
    assert_eq!(results[1]["reason"], json!("untrusted_payload_reference"));
}

#[test]
fn an_unknown_field_is_refused_rather_than_ignored() {
    let request: Result<DirectoryTrustRequestV1, _> = serde_json::from_value(json!({
        "schema": DIRECTORY_TRUST_REQUEST_SCHEMA,
        "request_id": "req-directory-trust",
        "guard_home": "/tmp/guard",
        "home_dir": "/tmp/home",
        "temp_dir": "/tmp",
        "candidates": [],
        "extra": true,
    }));
    assert!(request.is_err());
}

#[test]
fn a_request_for_another_schema_settles_nothing() {
    let body = evaluate(json!({
        "schema": "guard-directory-trust-request.v99",
        "request_id": "req-directory-trust",
        "guard_home": "/tmp/guard",
        "home_dir": "/tmp/home",
        "temp_dir": "/tmp",
        "candidates": [{"parameter": "home", "value": "/tmp/home"}],
    }));
    assert_eq!(body["status"], json!("error"));
    assert_eq!(
        body["code"],
        json!("native_directory_trust_schema_mismatch")
    );
    assert!(body.get("results").is_none());
}
