use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn base() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().expect("tempdir");
    let base = std::fs::canonicalize(directory.path()).expect("canonical tempdir");
    (directory, base)
}

fn project(path: &Path, manifest: &str) {
    std::fs::create_dir_all(path).expect("mkdir project");
    std::fs::write(path.join("package.json"), manifest).expect("write package.json");
}

fn spelled(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn scripts(source_path: Value) -> Value {
    json!({"surface": "package-scripts", "source_path": source_path, "state": null})
}

fn roots(cwd: &Path, include_cwd: bool, entries: Value) -> Vec<String> {
    let answer = dispatch(&json!({
        "op": "roots",
        "cwd": spelled(cwd),
        "include_cwd": include_cwd,
        "entries": entries,
    }))
    .expect("roots answer");
    serde_json::from_value(answer["roots"].clone()).expect("root list")
}

fn available(cwd: &Path, entries: Value) -> Vec<bool> {
    let answer = dispatch(&json!({"op": "available", "cwd": spelled(cwd), "entries": entries}))
        .expect("available answer");
    serde_json::from_value(answer["available"].clone()).expect("availability list")
}

fn operator_cwd(cwd: &Path, home: &Path, requested: Value) -> String {
    let answer = dispatch(&json!({
        "op": "operator_cwd",
        "cwd": spelled(cwd),
        "home": spelled(home),
        "requested": requested,
    }))
    .expect("operator_cwd answer");
    answer["path"].as_str().expect("path").to_owned()
}

#[test]
fn the_working_directory_is_a_root_only_when_asked_and_a_project() {
    let (_directory, base) = base();
    let app = base.join("app");
    project(&app, "{}");
    assert_eq!(roots(&app, true, json!([])), [spelled(&app)]);
    assert!(roots(&app, false, json!([])).is_empty());
    assert!(roots(&base, true, json!([])).is_empty());
}

#[test]
fn remembered_projects_follow_the_working_directory_once_each() {
    let (_directory, base) = base();
    let (app, lib) = (base.join("app"), base.join("lib"));
    project(&app, "{}");
    project(&lib, "{}");
    let entries = json!([
        scripts(json!(spelled(&lib.join("package.json")))),
        scripts(json!(spelled(&lib))),
        scripts(json!(spelled(&app))),
    ]);
    assert_eq!(roots(&app, true, entries), [spelled(&app), spelled(&lib)]);
}

#[test]
fn only_remembered_package_script_paths_are_roots() {
    let (_directory, base) = base();
    let lib = base.join("lib");
    project(&lib, "{}");
    let entries = json!([
        {"surface": "mcp", "source_path": spelled(&lib)},
        {"source_path": spelled(&lib)},
        scripts(json!("user-tool")),
        scripts(json!(7)),
        scripts(Value::Null),
    ]);
    assert!(roots(&base, false, entries).is_empty());
}

#[test]
fn a_relative_remembered_path_is_read_against_the_working_directory() {
    let (_directory, base) = base();
    let lib = base.join("lib");
    project(&lib, "{}");
    let entries = json!([scripts(json!("lib/package.json"))]);
    assert_eq!(roots(&base, false, entries), [spelled(&lib)]);
}

#[test]
fn a_project_whose_package_json_is_gone_is_not_a_root() {
    let (_directory, base) = base();
    let gone = base.join("gone");
    std::fs::create_dir(&gone).expect("mkdir gone");
    std::fs::create_dir(gone.join("package.json")).expect("directory named package.json");
    let entries = json!([
        scripts(json!(spelled(&gone))),
        scripts(json!(spelled(&base.join("missing"))))
    ]);
    assert!(roots(&base, false, entries).is_empty());
}

#[test]
fn a_symlinked_project_is_remembered_at_its_real_location() {
    let (_directory, base) = base();
    let real = base.join("real");
    project(&real, "{}");
    symlink(&real, base.join("alias")).expect("symlink");
    let entries = json!([
        scripts(json!(spelled(&base.join("alias")))),
        scripts(json!(spelled(&real)))
    ]);
    assert_eq!(roots(&base, false, entries), [spelled(&real)]);
}

#[test]
fn workspace_packages_follow_their_project_in_sorted_order() {
    let (_directory, base) = base();
    let mono = base.join("mono");
    project(&mono, r#"{"workspaces": ["packages/*"]}"#);
    project(&mono.join("packages/b"), "{}");
    project(&mono.join("packages/.hidden"), "{}");
    project(&mono.join("packages/a"), "{}");
    std::fs::create_dir_all(mono.join("packages/no-manifest")).expect("mkdir");
    std::fs::write(mono.join("packages/file"), "").expect("write file");
    let entries = json!([scripts(json!(spelled(&mono)))]);
    assert_eq!(
        roots(&base, false, entries),
        [
            spelled(&mono),
            spelled(&mono.join("packages/.hidden")),
            spelled(&mono.join("packages/a")),
            spelled(&mono.join("packages/b")),
        ]
    );
}

#[test]
fn workspace_package_lists_take_the_object_form_and_literal_segments() {
    let (_directory, base) = base();
    let mono = base.join("mono");
    project(
        &mono,
        r#"{"workspaces": {"packages": ["./apps/web", "libs/*/pkg", "missing/*", 3]}}"#,
    );
    project(&mono.join("apps/web"), "{}");
    project(&mono.join("libs/one/pkg"), "{}");
    let entries = json!([scripts(json!(spelled(&mono)))]);
    assert_eq!(
        roots(&base, false, entries),
        [
            spelled(&mono),
            spelled(&mono.join("apps/web")),
            spelled(&mono.join("libs/one/pkg")),
        ]
    );
}

#[test]
fn workspace_patterns_that_leave_the_project_are_skipped() {
    let (_directory, base) = base();
    let mono = base.join("mono");
    let outside = base.join("outside");
    project(&outside, "{}");
    let absolute = format!("{}/*", spelled(&base));
    let manifest = json!({"workspaces": ["../outside", absolute, "**/x", "", "."]}).to_string();
    project(&mono, &manifest);
    let entries = json!([scripts(json!(spelled(&mono)))]);
    assert_eq!(roots(&base, false, entries), [spelled(&mono)]);
}

#[test]
fn a_linked_workspace_package_outside_the_project_is_skipped() {
    let (_directory, base) = base();
    let mono = base.join("mono");
    project(&mono, r#"{"workspaces": ["packages/*"]}"#);
    project(&mono.join("packages/inside"), "{}");
    project(&base.join("outside"), "{}");
    symlink(base.join("outside"), mono.join("packages/linked")).expect("symlink");
    let entries = json!([scripts(json!(spelled(&mono)))]);
    assert_eq!(
        roots(&base, false, entries),
        [spelled(&mono), spelled(&mono.join("packages/inside"))]
    );
}

#[test]
fn only_six_patterns_and_eight_workspace_packages_are_read() {
    let (_directory, base) = base();
    let mono = base.join("mono");
    let patterns: Vec<String> = (0..7).map(|index| format!("p{index}")).collect();
    project(&mono, &json!({"workspaces": patterns}).to_string());
    for index in 0..7 {
        project(&mono.join(format!("p{index}")), "{}");
    }
    let entries = json!([scripts(json!(spelled(&mono)))]);
    assert_eq!(roots(&base, false, entries).len(), 1 + 6);

    let wide = base.join("wide");
    project(&wide, r#"{"workspaces": ["w/*"]}"#);
    for index in 0..10 {
        project(&wide.join(format!("w/{index}")), "{}");
    }
    let entries = json!([scripts(json!(spelled(&wide)))]);
    assert_eq!(roots(&base, false, entries).len(), 1 + 8);
}

#[test]
fn malformed_package_json_has_no_workspace_packages() {
    let (_directory, base) = base();
    for (name, manifest) in [
        ("a", "not json"),
        ("b", "[1]"),
        ("c", r#"{"workspaces": "x/*"}"#),
    ] {
        let root = base.join(name);
        project(&root, manifest);
        project(&root.join("x/pkg"), "{}");
        let entries = json!([scripts(json!(spelled(&root)))]);
        assert_eq!(roots(&base, false, entries), [spelled(&root)]);
    }
}

#[test]
fn the_root_list_stops_growing_past_sixteen() {
    let (_directory, base) = base();
    let entries: Vec<Value> = (0..20)
        .map(|index| {
            let root = base.join(format!("p{index:02}"));
            project(&root, "{}");
            scripts(json!(spelled(&root)))
        })
        .collect();
    assert_eq!(roots(&base, false, json!(entries)).len(), 16);
}

#[test]
fn items_without_a_project_manifest_drop_out_unless_a_choice_was_saved() {
    let (_directory, base) = base();
    let app = base.join("app");
    project(&app, "{}");
    let missing = spelled(&base.join("missing"));
    let entries = json!([
        scripts(json!(spelled(&app))),
        scripts(json!(spelled(&app.join("package.json")))),
        scripts(json!("app")),
        scripts(json!(missing)),
        {"surface": "package-scripts", "source_path": missing, "state": "allowed"},
        {"surface": "package-scripts", "source_path": missing, "state": "blocked"},
        {"surface": "mcp", "source_path": missing},
        scripts(json!("system-bin")),
        scripts(Value::Null),
    ]);
    assert_eq!(
        available(&base, entries),
        [true, true, true, false, true, true, true, true, true]
    );
}

#[test]
fn the_operator_directory_wins_when_it_exists() {
    let (_directory, base) = base();
    let (home, work) = (base.join("home"), base.join("work"));
    std::fs::create_dir_all(&home).expect("mkdir home");
    std::fs::create_dir_all(&work).expect("mkdir work");
    symlink(&work, base.join("alias")).expect("symlink");
    let chosen = operator_cwd(&base, &home, json!(spelled(&base.join("alias"))));
    assert_eq!(chosen, spelled(&work));
}

#[test]
fn the_working_directory_is_used_only_inside_a_package_project() {
    let (_directory, base) = base();
    let home = base.join("home");
    let nested = home.join("app/src/deep");
    std::fs::create_dir_all(&nested).expect("mkdir nested");
    let missing = json!(spelled(&base.join("missing")));
    assert_eq!(
        operator_cwd(&nested, &home, missing.clone()),
        spelled(&home)
    );
    project(&home.join("app"), "{}");
    assert_eq!(operator_cwd(&nested, &home, missing), spelled(&nested));
    assert_eq!(operator_cwd(&nested, &home, Value::Null), spelled(&nested));
}

#[test]
fn the_package_json_walk_stops_at_the_home() {
    let (_directory, base) = base();
    project(&base, "{}");
    let home = base.join("home");
    let inside = home.join("work");
    std::fs::create_dir_all(&inside).expect("mkdir");
    assert_eq!(operator_cwd(&inside, &home, Value::Null), spelled(&home));
}

#[test]
fn the_package_json_walk_reads_a_few_levels_only() {
    let (_directory, base) = base();
    project(&base, "{}");
    let deep = base.join("a/b/c/d/e/f/g/h");
    std::fs::create_dir_all(&deep).expect("mkdir deep");
    let home = base.join("elsewhere");
    assert_eq!(operator_cwd(&deep, &home, Value::Null), spelled(&home));
    let shallow = base.join("a/b/c/d/e/f/g");
    assert_eq!(
        operator_cwd(&shallow, &home, Value::Null),
        spelled(&shallow)
    );
}

#[test]
fn malformed_requests_are_refused() {
    let (_directory, base) = base();
    let cwd = spelled(&base);
    for request in [
        json!({"op": "roots", "cwd": cwd, "include_cwd": true}),
        json!({"op": "roots", "cwd": cwd, "include_cwd": "yes", "entries": []}),
        json!({"op": "roots", "cwd": "relative", "include_cwd": true, "entries": []}),
        json!({"op": "roots", "cwd": cwd, "include_cwd": true, "entries": [1]}),
        json!({"op": "available", "cwd": cwd, "entries": {}}),
        json!({"op": "available", "cwd": cwd, "entries": [], "extra": 1}),
        json!({"op": "operator_cwd", "cwd": cwd, "home": "relative", "requested": null}),
        json!({"op": "operator_cwd", "cwd": cwd, "home": cwd, "requested": "relative"}),
        json!({"op": "operator_cwd", "cwd": cwd, "home": cwd}),
        json!({"op": "other", "cwd": cwd}),
        json!([]),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
