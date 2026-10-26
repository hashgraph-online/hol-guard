//! Tests for the route a later read runs in, which decides whether a proven
//! refresh answers for it.

use super::read_route;
use crate::CommandSegmentV1;

fn segment(arguments: &[&str]) -> CommandSegmentV1 {
    let arguments: Vec<String> = arguments.iter().map(|word| (*word).to_owned()).collect();
    let text = format!("git {}", arguments.join(" "));
    CommandSegmentV1 {
        tokens: std::iter::once("git".to_owned())
            .chain(arguments.iter().cloned())
            .collect(),
        executable: Some("git".to_owned()),
        arguments,
        environment_names: Vec::new(),
        wrapper_chain: Vec::new(),
        path_overridden: false,
        execution_context: "direct".to_owned(),
        pipeline_index: 0,
        span: crate::CommandSpanV1 {
            source: text.clone(),
            start: 0,
            end: text.len(),
        },
        text,
    }
}

fn context(cwd: &str) -> super::super::PathContext<'_> {
    super::super::PathContext {
        cwd: Some(cwd),
        ..Default::default()
    }
}

fn checkout() -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("guard-read-route-{}", std::process::id()));
    std::fs::create_dir_all(root.join("vendor/pinned")).expect("fixture");
    std::fs::canonicalize(root).expect("fixture")
}

#[test]
fn a_plain_read_runs_in_the_working_directory() {
    let root = checkout();
    let cwd = root.to_string_lossy().into_owned();
    for arguments in [&["status", "-sb"][..], &["--no-pager", "log", "-1"]] {
        assert_eq!(
            read_route(&segment(arguments), context(&cwd)).as_deref(),
            Some(root.as_path()),
            "{arguments:?}"
        );
    }
}

/// A fetched commit may add a directory Git reads as a repository of its own,
/// so a read routed below the checkout is not the one the refresh proved.
#[test]
fn a_leading_route_folds_as_git_folds_it() {
    let root = checkout();
    let cwd = root.to_string_lossy().into_owned();
    let nested = root.join("vendor/pinned");
    assert_eq!(
        read_route(&segment(&["-C", "vendor/pinned", "status"]), context(&cwd)).as_deref(),
        Some(nested.as_path())
    );
    assert_eq!(
        read_route(
            &segment(&["-C", "vendor", "-C", "pinned", "status"]),
            context(&cwd)
        )
        .as_deref(),
        Some(nested.as_path())
    );
    assert_eq!(
        read_route(
            &segment(&["-C", "vendor", "-C", &nested.to_string_lossy(), "status"]),
            context(&cwd)
        )
        .as_deref(),
        Some(nested.as_path())
    );
}

/// Every other leading option could send the read somewhere this cannot name.
#[test]
fn an_unnamed_route_is_refused() {
    let root = checkout();
    let cwd = root.to_string_lossy().into_owned();
    for arguments in [
        &["--git-dir=vendor/pinned/.git", "status"][..],
        &["--work-tree", "vendor", "status"],
        &["-Cvendor/pinned", "status"],
    ] {
        assert_eq!(
            read_route(&segment(arguments), context(&cwd)),
            None,
            "{arguments:?}"
        );
    }
    assert_eq!(
        read_route(&segment(&["status"]), super::super::PathContext::default()),
        None
    );
}
