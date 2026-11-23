//! Tests for the directory a Node runner names: how `--cwd` is read, reduced
//! to the workspace and carried into the contained run.

use super::super::tests::{route, tool, words};
use super::super::{node_tool_route, NodeToolRoute};
use super::named_run_directory;
use std::path::Path;

#[test]
fn the_directory_bun_names_travels_with_the_run() {
    let NodeToolRoute::Tool {
        name,
        arguments,
        directory,
        ..
    } = route(&["bunx", "--cwd", "packages/app", "tsc", "--noEmit"])
    else {
        panic!("the named directory keeps the run");
    };
    assert_eq!(name, "tsc");
    assert_eq!(arguments, words(&["--noEmit"]));
    assert_eq!(directory.as_deref(), Some("packages/app"));
    let NodeToolRoute::Tool { directory, .. } = route(&[
        "bunx",
        "--cwd=packages/app",
        "--no-install",
        "tsc",
        "--noEmit",
    ]) else {
        panic!("the joined spelling names the same directory");
    };
    assert_eq!(directory.as_deref(), Some("packages/app"));
}

#[test]
fn a_run_that_names_no_directory_carries_none() {
    let NodeToolRoute::Tool { directory, .. } = route(&["bunx", "eslint", "src"]) else {
        panic!("an ordinary local-bin run is still a run");
    };
    assert_eq!(directory, None);
}

#[test]
fn the_absolute_spelling_of_a_directory_names_the_same_run() {
    let base = Path::new("/workspace/portal");
    // Below the directory the command was made from: carried as the remainder.
    assert_eq!(
        named_run_directory("/workspace/portal/app", Some(base)),
        Some(Some("app".to_owned()))
    );
    assert_eq!(
        named_run_directory("/workspace/portal/packages/app", Some(base)),
        Some(Some("packages/app".to_owned()))
    );
    // The command's own directory names no subdirectory, so the run stands
    // where it already stood.
    assert_eq!(
        named_run_directory("/workspace/portal", Some(base)),
        Some(None)
    );
    assert_eq!(
        named_run_directory("/workspace/portal/", Some(base)),
        Some(None)
    );
    // A relative directory is carried as the command wrote it.
    assert_eq!(
        named_run_directory("packages/app", Some(base)),
        Some(Some("packages/app".to_owned()))
    );
}

#[test]
fn an_absolute_directory_the_command_does_not_stand_in_names_no_run() {
    let base = Path::new("/workspace/portal");
    for named in [
        // Outside the directory the command was made from.
        "/etc",
        "/workspace/other",
        // A sibling whose name only starts the same way.
        "/workspace/portal-notes",
        // Climbing back out of it.
        "/workspace/portal/../other",
        // Rewritten by the shell before Bun ever reads it.
        "~/portal",
        "$HOME/portal",
    ] {
        assert_eq!(named_run_directory(named, Some(base)), None, "{named}");
    }
    // With no directory to measure against, an absolute one names nothing.
    assert_eq!(named_run_directory("/workspace/portal/app", None), None);
}

// Bun reads a POSIX directory here. A Windows spelling carries a drive letter
// and separators the peel refuses on purpose, so the absolute arm is proved
// where it applies.
#[cfg(unix)]
#[test]
fn an_absolute_directory_travels_with_the_run() {
    let project = tempfile::tempdir().expect("a project directory");
    let base = project.path();
    std::fs::create_dir(base.join("app")).expect("a subdirectory to name");
    let NodeToolRoute::Tool { directory, .. } = node_tool_route(
        &words(&[
            "bunx",
            "--cwd",
            base.join("app").to_str().expect("a printable path"),
            "tsc",
            "--noEmit",
        ]),
        None,
        false,
        Some(base),
    ) else {
        panic!("the absolute spelling keeps the run");
    };
    assert_eq!(directory.as_deref(), Some("app"));
    let NodeToolRoute::Tool { directory, .. } = node_tool_route(
        &words(&[
            "bunx",
            "--cwd",
            base.to_str().expect("a printable path"),
            "tsc",
            "--noEmit",
        ]),
        None,
        false,
        Some(base),
    ) else {
        panic!("naming its own directory is still a run");
    };
    assert_eq!(directory, None);
}

#[test]
fn a_directory_outside_the_run_is_not_peeled() {
    // Each of these stands where the tool's name is read, so no supported
    // tool answers to it and the command keeps its ordinary review.
    for command in [
        ["bunx", "--cwd", "/etc", "tsc", "--noEmit"].as_slice(),
        ["bunx", "--cwd", "../elsewhere", "tsc", "--noEmit"].as_slice(),
        ["bunx", "--cwd", "~/elsewhere", "tsc", "--noEmit"].as_slice(),
        ["bunx", "--cwd", "$HOME", "tsc", "--noEmit"].as_slice(),
        ["bunx", "--cwd=/etc", "tsc", "--noEmit"].as_slice(),
        // A second directory would leave the run in one of two places.
        [
            "bunx",
            "--cwd",
            "packages/app",
            "--cwd",
            "packages/kit",
            "tsc",
            "--noEmit",
        ]
        .as_slice(),
        // npm has no such option, so the word is npm's package name.
        ["npx", "--cwd", "packages/app", "tsc", "--noEmit"].as_slice(),
    ] {
        assert!(tool(&route(command)).is_none(), "{command:?}");
    }
}

#[test]
fn a_drive_prefixed_directory_names_no_subdirectory() {
    // `C:/repo/other` has no leading separator, so the absolute branch never
    // reads it, yet Windows resolves it from that drive's root. `C:other`
    // resolves from whatever directory the process last held on the drive.
    // Neither is below the command's own directory, so the peel stops and the
    // command keeps its review.
    for named in ["C:/repo/other", "c:/repo/other", "C:other", "Z:"] {
        assert_eq!(named_run_directory(named, None), None, "{named}");
        assert_eq!(
            named_run_directory(named, Some(Path::new("/repo"))),
            None,
            "{named}"
        );
        assert!(
            tool(&route(&["bunx", "--cwd", named, "tsc", "--noEmit"])).is_none(),
            "{named}"
        );
    }
}
