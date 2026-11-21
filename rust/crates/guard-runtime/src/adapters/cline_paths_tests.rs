use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::{dispatch, Cline};
use crate::runner_authority_op::ERR_INVALID;

const UNSET: [&str; 2] = ["", ""];

struct Homes {
    _directory: tempfile::TempDir,
    base: PathBuf,
    home: PathBuf,
    guard: PathBuf,
}

fn homes() -> Homes {
    let directory = tempfile::tempdir().expect("tempdir");
    let base = std::fs::canonicalize(directory.path()).expect("canonical tempdir");
    let home = base.join("home");
    std::fs::create_dir(&home).expect("mkdir home");
    Homes {
        _directory: directory,
        guard: base.join("guard"),
        base,
        home,
    }
}

fn request(home: &Path, guard: &Path, op: &str, data_dirs: [&str; 2], extra: Value) -> Value {
    let mut request = json!({
        "op": op,
        "home": home.to_str().unwrap(),
        "guard_home": guard.to_str().unwrap(),
        "cwd": home.to_str().unwrap(),
        "data_dirs": data_dirs,
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    request
}

fn ask(homes: &Homes, op: &str, data_dirs: [&str; 2], extra: Value) -> Value {
    dispatch(&request(&homes.home, &homes.guard, op, data_dirs, extra)).unwrap()
}

fn checked(answer: &Value) -> Result<PathBuf, String> {
    match answer.get("path") {
        Some(path) => Ok(PathBuf::from(path.as_str().unwrap())),
        None => Err(answer["refusal"].as_str().unwrap().to_owned()),
    }
}

fn check_as(home: &Path, guard: &Path, path: &Path) -> Result<PathBuf, String> {
    let request = request(
        home,
        guard,
        "check",
        UNSET,
        json!({ "path": path.to_str().unwrap() }),
    );
    checked(&dispatch(&request).unwrap())
}

fn check(homes: &Homes, path: &Path) -> Result<PathBuf, String> {
    check_as(&homes.home, &homes.guard, path)
}

fn refused(result: Result<PathBuf, String>, reason: &str) {
    let refusal = result.expect_err("refused");
    assert!(refusal.contains(reason), "{refusal}");
}

#[test]
fn a_trusted_root_is_not_itself_a_destination() {
    let homes = homes();
    refused(check(&homes, &homes.home), "escapes");
    refused(check(&homes, &homes.guard), "escapes");
}

#[test]
fn nul_and_parent_segments_are_refused_before_any_probe() {
    let homes = homes();
    refused(check(&homes, &homes.home.join("hook\0other")), "escapes");
    for suffix in [
        "../outside/hook",
        "nested/../hook",
        "nested/../../outside/hook",
        "..",
    ] {
        refused(check(&homes, &homes.home.join(suffix)), "escapes");
    }
}

#[test]
fn a_relative_destination_is_read_against_the_callers_directory() {
    let homes = homes();
    assert_eq!(
        check(&homes, Path::new("hooks/PreToolUse")),
        Ok(homes.home.join("hooks").join("PreToolUse"))
    );
}

#[test]
fn missing_destinations_under_either_root_are_valid_and_left_absent() {
    let homes = homes();
    for root in [&homes.home, &homes.guard] {
        let destination = root.join("Cline user data/hooks.v2/pré-tool.py");
        assert_eq!(check(&homes, &destination), Ok(destination.clone()));
        assert!(!destination.exists());
    }
}

#[test]
fn a_destination_outside_both_roots_escapes() {
    let homes = homes();
    for outside in [
        homes.base.join("outside/PreToolUse"),
        homes.base.join("home-other/index.js"),
    ] {
        refused(check(&homes, &outside), "escapes");
    }
}

#[test]
fn a_symlink_at_any_level_is_refused_without_following_it() {
    let homes = homes();
    for (existing, outside) in [(false, false), (true, false), (false, true), (true, true)] {
        let target = if outside { &homes.base } else { &homes.home }
            .join(format!("target-{existing}-{outside}"));
        if existing {
            std::fs::create_dir(&target).unwrap();
        }
        let link = homes.home.join(format!("link-{existing}-{outside}"));
        symlink(&target, &link).unwrap();
        refused(check(&homes, &link), "symlink");
        refused(check(&homes, &link.join("nested/PreToolUse")), "symlink");
        assert!(!target.join("nested").exists());
    }
}

#[test]
fn a_symlinked_trusted_root_is_refused_as_a_parent() {
    let homes = homes();
    std::fs::create_dir(&homes.guard).unwrap();
    for (root, home_alias) in [(&homes.home, true), (&homes.guard, false)] {
        let alias = homes.base.join(format!("alias-{home_alias}"));
        symlink(root, &alias).unwrap();
        let (home, guard) = if home_alias {
            (alias.clone(), homes.guard.clone())
        } else {
            (homes.home.clone(), alias.clone())
        };
        refused(
            check_as(&home, &guard, &alias.join("hook")),
            "parent is a symlink",
        );
    }
}

#[test]
fn the_physical_home_behind_an_alias_is_accepted() {
    let homes = homes();
    let alias = homes.base.join("home-alias");
    symlink(&homes.home, &alias).unwrap();
    let destination = homes.home.join("custom/plugins/hol-guard/index.js");
    assert_eq!(
        check_as(&alias, &homes.guard, &destination),
        Ok(destination.clone())
    );
}

#[test]
fn an_unsafe_component_is_refused_while_walking() {
    let homes = homes();
    let request = request(&homes.home, &homes.guard, "roots", UNSET, json!({}));
    let cline = Cline::new(request.as_object().unwrap()).unwrap();
    for component in ["..", "/"] {
        refused(
            cline.walk(&homes.home, Path::new(component)),
            "unsafe path component",
        );
    }
}

fn roots(homes: &Homes, data_dirs: [&str; 2]) -> (PathBuf, Vec<PathBuf>) {
    let answer = ask(homes, "roots", data_dirs, json!({}));
    let paths = answer["hook_roots"].as_array().unwrap();
    (
        PathBuf::from(answer["data_dir"].as_str().unwrap()),
        paths
            .iter()
            .map(|path| PathBuf::from(path.as_str().unwrap()))
            .collect(),
    )
}

#[test]
fn default_roots_cover_the_ui_and_the_cli() {
    let homes = homes();
    let home = &homes.home;
    assert_eq!(
        roots(&homes, UNSET),
        (
            home.join(".cline"),
            vec![
                home.join("Documents/Cline/Hooks"),
                home.join(".cline/hooks")
            ]
        )
    );
    let outside = homes.base.join("outside");
    assert_eq!(
        roots(&homes, [outside.to_str().unwrap(), ""]).0,
        home.join(".cline")
    );
    let plugin = ask(&homes, "plugin_root", UNSET, json!({}));
    assert_eq!(checked(&plugin), Ok(home.join(".cline/plugins/hol-guard")));
}

#[test]
fn a_configured_data_directory_is_read_first() {
    let homes = homes();
    let current = homes.home.join("current-cline-data");
    let legacy = homes.home.join("legacy-cline-data");
    let (data_dir, hook_roots) = roots(
        &homes,
        [current.to_str().unwrap(), legacy.to_str().unwrap()],
    );
    assert_eq!(data_dir, current);
    assert_eq!(
        hook_roots,
        vec![
            current.join("hooks"),
            homes.home.join("Documents/Cline/Hooks"),
            homes.home.join(".cline/hooks"),
        ]
    );
    assert_eq!(roots(&homes, ["", legacy.to_str().unwrap()]).0, legacy);
    let plugin = ask(
        &homes,
        "plugin_root",
        ["", legacy.to_str().unwrap()],
        json!({}),
    );
    assert_eq!(checked(&plugin), Ok(legacy.join("plugins/hol-guard")));
}

#[test]
fn a_symlinked_plugin_root_is_refused() {
    let homes = homes();
    std::fs::create_dir(homes.base.join("elsewhere")).unwrap();
    symlink(homes.base.join("elsewhere"), homes.home.join(".cline")).unwrap();
    let plugin = ask(&homes, "plugin_root", UNSET, json!({}));
    refused(checked(&plugin), "symlink");
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn recorded_paths_bind_only_to_their_own_slots() {
    let homes = homes();
    let hooks = homes.home.join(".cline/hooks");
    let workers = homes.guard.join("managed/cline/hook-workers");
    let outside = homes.base.join("other/PostToolUse");
    for path in [
        hooks.join("PreToolUse"),
        hooks.join("TaskStart"),
        workers.join("PreToolUse.json"),
        workers.join("TaskStart.py"),
        outside.clone(),
    ] {
        write(&path, "x");
    }
    let answer = ask(
        &homes,
        "state_paths",
        UNSET,
        json!({
            "paths": {
                "PreToolUse": hooks.join("PreToolUse").to_str().unwrap(),
                "PostToolUse": outside.to_str().unwrap(),
                "TaskStart": "relative/TaskStart",
                "TaskError": 7,
                "SessionShutdown": hooks.join("TaskStart").to_str().unwrap(),
            },
            "workers": {
                "PreToolUse": workers.join("PreToolUse.json").to_str().unwrap(),
                "TaskStart": workers.join("TaskStart.py").to_str().unwrap(),
            },
            "root": null,
        }),
    );
    assert_eq!(
        answer,
        json!({
            "paths": {
                "PreToolUse": hooks.join("PreToolUse").to_str().unwrap(),
                "PostToolUse": null,
                "UserPromptSubmit": null,
                "TaskStart": null,
                "TaskError": null,
                "SessionShutdown": null,
            },
            "workers": {
                "PreToolUse": workers.join("PreToolUse.json").to_str().unwrap(),
                "PostToolUse": null,
                "UserPromptSubmit": null,
                "TaskStart": workers.join("TaskStart.py").to_str().unwrap(),
                "TaskError": null,
                "SessionShutdown": null,
            },
        })
    );
}

#[test]
fn a_saved_custom_root_still_binds_after_its_override_changes() {
    let homes = homes();
    let hooks = homes.home.join("custom data/Hooks");
    write(&hooks.join("PreToolUse"), "x");
    let request = request(&homes.home, &homes.guard, "roots", UNSET, json!({}));
    let cline = Cline::new(request.as_object().unwrap()).unwrap();
    assert_eq!(
        cline.saved_hook_root(&json!(hooks.to_str().unwrap())),
        Some(hooks.clone())
    );
    for unusable in [
        json!(hooks.join("missing/Hooks").to_str().unwrap()),
        json!(homes.guard.join("Hooks").to_str().unwrap()),
        json!(homes.home.join("custom data").to_str().unwrap()),
        json!("Hooks"),
        json!(""),
        json!(null),
    ] {
        assert_eq!(cline.saved_hook_root(&unusable), None, "{unusable}");
    }
    let answer = ask(
        &homes,
        "state_paths",
        UNSET,
        json!({
            "paths": { "PreToolUse": hooks.join("PreToolUse").to_str().unwrap() },
            "workers": null,
            "root": hooks.to_str().unwrap(),
        }),
    );
    assert_eq!(
        answer["paths"]["PreToolUse"],
        json!(hooks.join("PreToolUse").to_str().unwrap())
    );
}

#[test]
fn uninstall_removes_only_managed_hooks_bound_to_their_slots() {
    let homes = homes();
    let hooks = homes.home.join(".cline/hooks");
    let workers = homes.guard.join("managed/cline/hook-workers");
    let state = homes.guard.join("managed/cline/native-hooks-state.json");
    let managed = format!("#!/bin/sh\n# {}\n", super::MARKER);
    write(&hooks.join("PreToolUse"), &managed);
    write(&hooks.join("PostToolUse"), "edited by the user\n");
    write(&workers.join("PreToolUse.json"), &managed);
    let stray = homes.base.join("stray/TaskStart");
    write(&stray, &managed);
    let recorded = json!({
        "root": hooks.to_str().unwrap(),
        "paths": {
            "PreToolUse": hooks.join("PreToolUse").to_str().unwrap(),
            "PostToolUse": hooks.join("PostToolUse").to_str().unwrap(),
            "TaskStart": stray.to_str().unwrap(),
            "TaskError": hooks.join("TaskError").to_str().unwrap(),
        },
        "workers": { "PreToolUse": workers.join("PreToolUse.json").to_str().unwrap() },
    });
    write(&state, &recorded.to_string());
    assert_eq!(
        ask(&homes, "uninstall", UNSET, json!({})),
        json!({
            "transport": "hooks",
            "complete": false,
            "removed": [
                hooks.join("PreToolUse").to_str().unwrap(),
                workers.join("PreToolUse.json").to_str().unwrap(),
            ],
            "retained_modified_or_unowned": [
                hooks.join("PostToolUse").to_str().unwrap(),
                stray.to_str().unwrap(),
            ],
        })
    );
    assert!(state.is_file() && stray.is_file() && hooks.join("PostToolUse").is_file());

    std::fs::remove_file(hooks.join("PostToolUse")).unwrap();
    std::fs::remove_file(&stray).unwrap();
    let answer = ask(&homes, "uninstall", UNSET, json!({}));
    assert_eq!(answer["complete"], json!(true));
    assert!(!state.exists());
}

#[test]
fn uninstall_without_a_record_has_nothing_to_remove() {
    let homes = homes();
    assert_eq!(
        ask(&homes, "uninstall", UNSET, json!({})),
        json!({
            "transport": "hooks",
            "complete": true,
            "removed": [],
            "retained_modified_or_unowned": [],
        })
    );
}

#[test]
fn refuses_malformed_requests() {
    let homes = homes();
    let home = homes.home.to_str().unwrap();
    let valid = request(&homes.home, &homes.guard, "roots", UNSET, json!({}));
    let mut cases = vec![
        json!([]),
        request(&homes.home, &homes.guard, "other", UNSET, json!({})),
        request(&homes.home, &homes.guard, "check", UNSET, json!({})),
        request(
            &homes.home,
            &homes.guard,
            "check",
            UNSET,
            json!({ "path": 1 }),
        ),
        request(
            &homes.home,
            &homes.guard,
            "roots",
            UNSET,
            json!({ "path": "x" }),
        ),
        request(
            &homes.home,
            &homes.guard,
            "state_paths",
            UNSET,
            json!({ "paths": {} }),
        ),
        request(Path::new("home"), &homes.guard, "roots", UNSET, json!({})),
    ];
    for (key, value) in [
        ("data_dirs", json!([""])),
        ("data_dirs", json!(["", 1])),
        ("cwd", json!("relative")),
        ("guard_home", json!(null)),
        ("home", json!(format!("{home}\0"))),
    ] {
        let mut case = valid.clone();
        case[key] = value;
        cases.push(case);
    }
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("cwd");
    cases.push(missing);
    for case in cases {
        assert_eq!(dispatch(&case), Err(ERR_INVALID), "{case}");
    }
}
