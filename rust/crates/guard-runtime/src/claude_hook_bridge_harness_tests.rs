use super::*;

fn lookup<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        pairs
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| (*value).to_owned())
    }
}

#[test]
fn a_claude_code_hook_drops_a_written_cursor_attribution() {
    let written = "guard-home=%2Fh&workspace=%2Fcursor%2Fproject&runtime-harness=cursor";
    assert_eq!(
        attributed_query(written, None),
        "guard-home=%2Fh&workspace=%2Fcursor%2Fproject"
    );
    // An encoded name is still the same parameter to the daemon.
    assert_eq!(
        attributed_query("guard-home=%2Fh&runtime%2Dharness=cursor", None),
        "guard-home=%2Fh"
    );
}

#[test]
fn a_claude_code_hook_leaves_an_unattributed_query_alone() {
    assert_eq!(
        attributed_query("guard-home=%2Fh&home=%2Fu", None),
        "guard-home=%2Fh&home=%2Fu"
    );
}

#[test]
fn a_cursor_hook_names_cursor_and_its_project() {
    let cursor = CursorRun {
        project_dir: Some("/work/app".to_owned()),
    };
    assert_eq!(
        attributed_query("guard-home=%2Fh&workspace=%2Fold", Some(&cursor)),
        "guard-home=%2Fh&workspace=%2Fwork%2Fapp&runtime-harness=cursor"
    );
    let without_project = CursorRun { project_dir: None };
    assert_eq!(
        attributed_query(
            "guard-home=%2Fh&runtime-harness=codex",
            Some(&without_project)
        ),
        "guard-home=%2Fh&runtime-harness=cursor"
    );
}

#[test]
fn claude_code_started_from_a_cursor_terminal_is_not_a_cursor_run() {
    let inherited = [
        ("CURSOR_TRACE_ID", "t"),
        ("CURSOR_PROJECT_DIR", "/work/app"),
        ("CLAUDECODE", "1"),
        ("CLAUDE_CODE_ENTRYPOINT", "cli"),
    ];
    assert_eq!(cursor_run(lookup(&inherited)), None);
    assert_eq!(
        attributed_query(
            "guard-home=%2Fh&runtime-harness=cursor",
            cursor_run(lookup(&inherited)).as_ref()
        ),
        "guard-home=%2Fh"
    );
    // Only Claude Code's own marker counts; a blank or other value does not.
    for value in ["", "0", "true"] {
        assert_eq!(
            cursor_run(lookup(&[("CURSOR_TRACE_ID", "t"), ("CLAUDECODE", value)])),
            Some(CursorRun { project_dir: None }),
            "{value}"
        );
    }
}

#[test]
fn only_a_set_cursor_marker_makes_a_cursor_run() {
    assert_eq!(cursor_run(lookup(&[])), None);
    assert_eq!(cursor_run(lookup(&[("CURSOR_TRACE_ID", "  ")])), None);
    assert_eq!(
        cursor_run(lookup(&[("CLAUDE_CODE_ENTRYPOINT", "claude-desktop")])),
        None
    );
    assert_eq!(
        cursor_run(lookup(&[("CURSOR_TRACE_ID", "t")])),
        Some(CursorRun { project_dir: None })
    );
    assert_eq!(
        cursor_run(lookup(&[
            ("CURSOR_VERSION", "2.1"),
            ("CURSOR_PROJECT_DIR", " /work/app "),
        ])),
        Some(CursorRun {
            project_dir: Some("/work/app".to_owned())
        })
    );
}
