use std::os::unix::process::CommandExt;

use super::*;

#[test]
fn checks_are_the_command_before_the_git_steps() {
    assert_eq!(checks("pytest && git push", "git push"), Some("pytest"));
    assert_eq!(checks(" a && b&&git push\n", "git push"), Some("a && b"));
    assert_eq!(checks("pytest; git push", "git push"), None);
    assert_eq!(checks("&& git push", "git push"), None);
    assert_eq!(checks("pytest && git push", ""), None);
    assert_eq!(checks("pytest && git push", "git pull"), None);
}

#[test]
fn a_host_step_searches_only_outside_the_workspace() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().canonicalize().unwrap();
    let workspace = base.join("project");
    std::fs::create_dir_all(workspace.join("bin")).unwrap();
    std::os::unix::fs::symlink(workspace.join("bin"), base.join("linked")).unwrap();
    let search_path = std::env::join_paths([
        "/usr/bin".into(),
        PathBuf::from("bin"),
        PathBuf::new(),
        workspace.clone(),
        workspace.join("bin"),
        base.join("linked"),
        workspace.join("missing/../.."),
        base.join("project-other"),
        "/bin".into(),
    ])
    .unwrap();
    assert_eq!(
        outside_search_path(&search_path, &workspace),
        std::env::join_paths([
            PathBuf::from("/usr/bin"),
            workspace.join("missing/../.."),
            base.join("project-other"),
            "/bin".into(),
        ])
        .unwrap()
    );
}

#[test]
fn a_host_step_runs_without_git_location_and_with_the_outside_path() {
    let root = tempfile::tempdir().unwrap();
    let cwd = root.path().canonicalize().unwrap();
    let signals = process::Signals::idle();
    let mut launcher = Command::new("/usr/bin/env");
    launcher
        .env("GIT_DIR", "/elsewhere")
        .env("GIT_WORK_TREE", "/w");
    let script = concat!(
        "test -z \"${GIT_DIR+set}${GIT_WORK_TREE+set}\" || exit 2; ",
        "test \"$PATH\" = /usr/bin:/bin || exit 3; ",
        "test -f ./marker || exit 4; exit 7",
    );
    std::fs::write(cwd.join("marker"), "").unwrap();
    let ran = run_launched(
        launcher,
        script,
        &GIT_LOCATION,
        OsStr::new("/usr/bin:/bin"),
        &cwd,
        &signals,
        30,
    );
    assert_eq!(ran, Ok(7));
    // The launcher makes the step a group of its own; so does this one.
    let mut grouped = Command::new("/usr/bin/env");
    grouped.process_group(0);
    let slow = run_launched(
        grouped,
        "sleep 5",
        &GIT_LOCATION,
        OsStr::new("/usr/bin:/bin"),
        &cwd,
        &signals,
        1,
    );
    assert_eq!(slow.map_err(|failure| failure.exit_code), Err(124));
}

#[test]
fn an_unavailable_resident_is_asked_again_and_a_decision_is_not() {
    use std::cell::{Cell, RefCell};
    let answer = |code: &str| {
        let mut response = Map::new();
        response.insert("reason_code".to_owned(), Value::String(code.to_owned()));
        Some(response)
    };
    let code = |response: &Option<Map<String, Value>>| {
        response
            .as_ref()
            .map(|response| response["reason_code"].clone())
    };
    // Unavailable, then missing, then a decision: three asks, two pauses.
    let replies = RefCell::new(vec![
        answer("native_workspace_containment_required"),
        None,
        answer("native_pre_tool_unavailable"),
    ]);
    let pauses = Cell::new(0);
    let response = settled(
        || replies.borrow_mut().pop().unwrap(),
        |_| pauses.set(pauses.get() + 1),
    );
    assert_eq!(
        code(&response),
        Some(Value::String(
            "native_workspace_containment_required".to_owned()
        ))
    );
    assert_eq!(pauses.get(), 2);
    // A decision is never asked again, even one against the steps.
    let asks = Cell::new(0);
    let response = settled(
        || {
            asks.set(asks.get() + 1);
            answer("native_policy_block")
        },
        |_| panic!("a decision was asked again"),
    );
    assert_eq!(asks.get(), 1);
    assert_eq!(
        code(&response),
        Some(Value::String("native_policy_block".to_owned()))
    );
    // A resident that stays away is asked three times, then given up on.
    let asks = Cell::new(0);
    let response = settled(
        || {
            asks.set(asks.get() + 1);
            None
        },
        |_| {},
    );
    assert_eq!(asks.get(), 3);
    assert!(response.is_none());
}
