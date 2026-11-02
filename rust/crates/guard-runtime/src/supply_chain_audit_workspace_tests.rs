use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tempfile::TempDir;

use super::*;

fn base() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("temp dir");
    let base = fs::canonicalize(dir.path()).expect("canonical temp dir");
    (dir, base)
}

fn text(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn project(path: &Path) -> PathBuf {
    fs::create_dir_all(path).expect("project dir");
    fs::write(path.join("package.json"), b"{\"name\":\"demo\"}").expect("manifest");
    path.to_path_buf()
}

fn resolve_with(base: &Path, request: Value) -> Value {
    let mut args = json!({
        "allowed_roots": [text(base)],
        "user_home": text(&base.join("home")),
    });
    let fields = args.as_object_mut().expect("object");
    for (key, value) in request.as_object().expect("request object") {
        fields.insert(key.clone(), value.clone());
    }
    dispatch(&args).expect("workspace answer")
}

fn workspace(path: &Path) -> Value {
    json!({ "workspace_dir": text(path) })
}

#[test]
fn an_explicit_workspace_under_an_allowed_root_wins() {
    let (_dir, base) = base();
    let explicit = project(&base.join("explicit"));
    let managed = project(&base.join("managed"));
    let answer = resolve_with(
        &base,
        json!({
            "explicit": [text(&explicit), null],
            "managed_workspace_dirs": [text(&managed)],
        }),
    );
    assert_eq!(answer, workspace(&explicit));

    let alias = resolve_with(&base, json!({"explicit": [null, text(&explicit)]}));
    assert_eq!(alias, workspace(&explicit));
}

#[test]
fn an_explicit_workspace_needs_no_manifest_but_must_be_a_directory() {
    let (_dir, base) = base();
    let bare = base.join("bare");
    fs::create_dir_all(&bare).expect("bare dir");
    assert_eq!(
        resolve_with(&base, json!({"explicit": [text(&bare)]})),
        workspace(&bare)
    );

    let file = base.join("file.txt");
    fs::write(&file, b"x").expect("file");
    assert_eq!(
        resolve_with(&base, json!({"explicit": [text(&file)]})),
        json!({"workspace_dir": null})
    );
}

#[test]
fn an_invalid_explicit_workspace_falls_back_unless_the_caller_rejects_it() {
    let (_dir, base) = base();
    let managed = project(&base.join("managed"));
    let missing = text(&base.join("missing"));
    let request = json!({
        "explicit": [missing],
        "managed_workspace_dirs": [text(&managed)],
    });
    assert_eq!(resolve_with(&base, request.clone()), workspace(&managed));

    let mut rejecting = request;
    rejecting["reject_invalid_explicit"] = json!(true);
    assert_eq!(
        resolve_with(&base, rejecting),
        json!({"workspace_dir": null, "invalid_explicit": true})
    );
}

#[test]
fn a_blank_value_is_skipped_but_a_null_spelling_is_an_invalid_workspace() {
    let (_dir, base) = base();
    let managed = project(&base.join("managed"));
    for blank in ["", "   "] {
        let answer = resolve_with(
            &base,
            json!({
                "explicit": [blank],
                "managed_workspace_dirs": [text(&managed)],
                "reject_invalid_explicit": true,
            }),
        );
        assert_eq!(answer, workspace(&managed), "{blank:?}");
    }
    for spelling in ["None", " null "] {
        let request = json!({
            "explicit": [spelling],
            "managed_workspace_dirs": [text(&managed)],
        });
        assert_eq!(resolve_with(&base, request.clone()), workspace(&managed));
        let mut rejecting = request;
        rejecting["reject_invalid_explicit"] = json!(true);
        assert_eq!(
            resolve_with(&base, rejecting),
            json!({"workspace_dir": null, "invalid_explicit": true}),
            "{spelling:?}"
        );
    }
}

#[test]
fn a_workspace_outside_every_allowed_root_is_refused() {
    let (_dir, base) = base();
    let (_other_dir, other) = self::base();
    let outside = project(&other.join("outside"));
    let answer = resolve_with(
        &base,
        json!({
            "explicit": [text(&outside)],
            "cursor_project_dir": text(&outside),
            "cwd": text(&outside),
            "managed_workspace_dirs": [text(&outside)],
        }),
    );
    assert_eq!(answer, json!({"workspace_dir": null}));
}

#[test]
fn inference_takes_the_cursor_project_then_the_cwd_then_a_managed_install() {
    let (_dir, base) = base();
    let cursor = project(&base.join("cursor"));
    let cwd = project(&base.join("cwd"));
    let managed = project(&base.join("managed"));
    let request = json!({
        "cursor_project_dir": format!(" {} ", text(&cursor)),
        "cwd": text(&cwd),
        "managed_workspace_dirs": [text(&managed)],
    });
    assert_eq!(resolve_with(&base, request.clone()), workspace(&cursor));

    let mut without_cursor = request;
    without_cursor["cursor_project_dir"] = json!(text(&base.join("missing")));
    assert_eq!(resolve_with(&base, without_cursor.clone()), workspace(&cwd));

    let mut without_cwd = without_cursor;
    without_cwd["cwd"] = json!(text(&base));
    assert_eq!(resolve_with(&base, without_cwd), workspace(&managed));
}

#[test]
fn an_inferred_workspace_must_hold_a_dependency_manifest() {
    let (_dir, base) = base();
    let empty = base.join("empty");
    fs::create_dir_all(&empty).expect("empty dir");
    let managed = project(&base.join("managed"));
    fs::create_dir_all(base.join("managed-rust")).expect("rust dir");
    fs::write(base.join("managed-rust/Cargo.toml"), b"").expect("cargo manifest");
    let answer = resolve_with(
        &base,
        json!({
            "cursor_project_dir": text(&empty),
            "cwd": text(&empty),
            "managed_workspace_dirs": [text(&empty), text(&base.join("managed-rust")), text(&managed)],
        }),
    );
    assert_eq!(answer, workspace(&base.join("managed-rust")));
}

#[test]
fn home_and_relative_spellings_resolve_against_the_callers_home_and_cwd() {
    let (_dir, base) = base();
    let in_home = project(&base.join("home/projects/app"));
    assert_eq!(
        resolve_with(&base, json!({"explicit": ["~/projects/app"]})),
        workspace(&in_home)
    );
    assert_eq!(
        resolve_with(
            &base,
            json!({"explicit": ["projects/app"], "cwd": text(&base.join("home"))})
        ),
        workspace(&in_home)
    );
    assert_eq!(
        resolve_with(&base, json!({"explicit": ["projects/app"]})),
        json!({"workspace_dir": null})
    );
    assert_eq!(
        resolve_with(&base, json!({"explicit": ["~someone/projects/app"]})),
        json!({"workspace_dir": null})
    );
}

#[cfg(unix)]
#[test]
fn a_link_that_leaves_the_allowed_roots_is_refused() {
    let (_dir, base) = base();
    let (_other_dir, other) = self::base();
    let outside = project(&other.join("outside"));
    let root = base.join("root");
    fs::create_dir_all(&root).expect("root");
    let linked = root.join("linked");
    std::os::unix::fs::symlink(&outside, &linked).expect("symlink");
    let answer = dispatch(&json!({
        "explicit": [text(&linked)],
        "allowed_roots": [text(&root)],
    }))
    .expect("workspace answer");
    assert_eq!(answer, json!({"workspace_dir": null}));
}

#[test]
fn traversal_and_a_sibling_sharing_the_root_prefix_are_refused() {
    let (_dir, base) = base();
    let root = base.join("root");
    fs::create_dir_all(&root).expect("root");
    let sibling = base.join("root-other");
    fs::create_dir_all(&sibling).expect("sibling");
    for candidate in [sibling.clone(), root.join("..").join("root-other")] {
        let answer = dispatch(&json!({
            "explicit": [text(&candidate)],
            "allowed_roots": [text(&root)],
        }))
        .expect("workspace answer");
        assert_eq!(answer, json!({"workspace_dir": null}), "{candidate:?}");
    }
}

#[cfg(unix)]
#[test]
fn a_workspace_under_a_linked_allowed_root_resolves_to_its_target() {
    let (_dir, base) = base();
    let real_root = base.join("real-root");
    let target = real_root.join("workspace");
    fs::create_dir_all(&target).expect("workspace");
    let linked_root = base.join("linked-root");
    std::os::unix::fs::symlink(&real_root, &linked_root).expect("symlink");
    let answer = dispatch(&json!({
        "explicit": [text(&linked_root.join("workspace"))],
        "allowed_roots": [text(&linked_root)],
    }))
    .expect("workspace answer");
    assert_eq!(answer, workspace(&target));
}

#[test]
fn malformed_requests_are_invalid() {
    for args in [
        json!([]),
        json!({"explicit": "x"}),
        json!({"allowed_roots": {}}),
        json!({"managed_workspace_dirs": 1}),
        json!({"cwd": 1}),
        json!({"cursor_project_dir": []}),
        json!({"reject_invalid_explicit": "yes"}),
    ] {
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{args}");
    }
}
