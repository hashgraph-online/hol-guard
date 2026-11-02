use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use tempfile::TempDir;

use super::*;

struct Layout {
    _dir: TempDir,
    base: PathBuf,
    guard_home: PathBuf,
    shims: PathBuf,
    tools: PathBuf,
}

fn layout() -> Layout {
    // Not canonicalized: a Windows canonical path is verbatim, where `/` in
    // an entry would not separate components. Both sides resolve the same
    // way, so links in the temp path cancel out.
    let dir = TempDir::new().expect("temp dir");
    let base = dir.path().to_path_buf();
    let guard_home = base.join("home").join(".hol-guard");
    let shims = guard_home.join("package-shims").join("bin");
    let tools = base.join("tools").join("bin");
    fs::create_dir_all(&shims).expect("shim dir");
    fs::create_dir_all(&tools).expect("tool dir");
    Layout {
        _dir: dir,
        base,
        guard_home,
        shims,
        tools,
    }
}

fn text(path: &Path) -> String {
    path.to_str().expect("utf-8 path").to_owned()
}

fn launch_path(layout: &Layout, path: &str, separator: &str) -> Value {
    dispatch(&json!({
        "guard_home": text(&layout.guard_home),
        "launch_cwd": text(&layout.base),
        "user_home": text(&layout.base.join("home")),
        "separator": separator,
        "path": path,
    }))
    .expect("launch path answer")
}

#[test]
fn the_shim_directory_and_empty_entries_are_dropped() {
    let layout = layout();
    let missing = layout.base.join("missing").join("bin");
    let path = [
        text(&layout.shims),
        String::new(),
        text(&layout.tools),
        text(&missing),
    ]
    .join(";");
    assert_eq!(
        launch_path(&layout, &path, ";"),
        json!({ "path": [text(&layout.tools), text(&missing)].join(";") })
    );
}

#[test]
fn other_entries_keep_their_spelling() {
    let layout = layout();
    let spelled = format!("{}/../bin/", text(&layout.tools));
    fs::create_dir_all(layout.base.join("bin")).expect("sibling bin");
    let path = [spelled.as_str(), "tools/bin", "~/bin"].join(";");
    assert_eq!(launch_path(&layout, &path, ";"), json!({ "path": path }));
}

#[test]
fn relative_and_home_spellings_of_the_shims_are_dropped() {
    let layout = layout();
    let path = [
        "home/.hol-guard/package-shims/bin",
        "~/.hol-guard/package-shims/bin",
        "home/.hol-guard/package-shims/bin/../bin",
        &text(&layout.tools),
    ]
    .join(";");
    assert_eq!(
        launch_path(&layout, &path, ";"),
        json!({ "path": text(&layout.tools) })
    );
}

#[test]
fn an_entry_that_cannot_be_resolved_refuses_the_launch() {
    let layout = layout();
    for entry in ["invalid\0path", "~someone/bin"] {
        let path = format!("{};{entry}", text(&layout.tools));
        assert_eq!(
            launch_path(&layout, &path, ";"),
            json!({ "refused": "path_unverified" }),
            "{entry:?}"
        );
    }
    let homeless = dispatch(&json!({
        "guard_home": text(&layout.guard_home),
        "launch_cwd": text(&layout.base),
        "separator": ";",
        "path": "~/bin",
    }))
    .expect("launch path answer");
    assert_eq!(homeless, json!({ "refused": "path_unverified" }));
}

#[test]
fn an_unset_path_stays_empty() {
    let layout = layout();
    assert_eq!(launch_path(&layout, "", ":"), json!({ "path": "" }));
}

#[cfg(unix)]
#[test]
fn a_link_to_the_shims_is_dropped_and_a_looping_shim_home_refuses() {
    let layout = layout();
    let linked = layout.base.join("linked-shims");
    std::os::unix::fs::symlink(&layout.shims, &linked).expect("symlink");
    let path = [text(&linked), text(&layout.tools)].join(":");
    assert_eq!(
        launch_path(&layout, &path, ":"),
        json!({ "path": text(&layout.tools) })
    );

    let looping_home = layout.base.join("looping");
    fs::create_dir_all(&looping_home).expect("looping home");
    let shim_root = looping_home.join("package-shims");
    std::os::unix::fs::symlink(&shim_root, &shim_root).expect("self link");
    let answer = dispatch(&json!({
        "guard_home": text(&looping_home),
        "launch_cwd": text(&layout.base),
        "separator": ":",
        "path": text(&layout.tools),
    }))
    .expect("launch path answer");
    assert_eq!(answer, json!({ "refused": "shim_unverified" }));
}

#[test]
fn malformed_requests_are_invalid() {
    let layout = layout();
    let valid = json!({
        "guard_home": text(&layout.guard_home),
        "launch_cwd": text(&layout.base),
        "separator": ":",
        "path": "",
    });
    assert!(dispatch(&valid).is_ok());
    for (key, value) in [
        ("guard_home", json!("relative/home")),
        ("guard_home", Value::Null),
        ("launch_cwd", json!("relative")),
        ("user_home", json!(1)),
        ("user_home", json!("relative")),
        ("separator", json!(",")),
        ("path", json!(["/bin"])),
        ("path", json!("x".repeat(MAX_PATH_BYTES + 1))),
    ] {
        let mut args = valid.clone();
        args[key] = value;
        assert_eq!(dispatch(&args), Err(ERR_INVALID), "{key}");
    }
    assert_eq!(dispatch(&json!([])), Err(ERR_INVALID));
}
