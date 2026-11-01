//! The text a contained call is routed and decided as, and the directories
//! a leading `cd` may name for the native sink.

use serde_json::{Map, Value};

/// The call the denial was answered for, when a trailing group or a
/// virtualenv activation moved it. `source .venv/bin/activate && pytest -q`
/// exports settings and runs nothing else, so the pre-tool pass hands the
/// verdict to `pytest` and answers for `.venv/bin/pytest -q`; and
/// `(.venv/bin/pytest -q)` runs exactly the list inside its parentheses, so
/// the pass answers for that list. The sink plans the command it is given,
/// and it models neither a shell builtin nor a group, so handing it the
/// unprojected text leaves it unable to build a plan for a call Guard already
/// judged. This cannot widen authority: the sink reruns native authority on
/// the snapshot and needs a matching denial of its own, and the projected
/// text is the user's own command with the wrapping it already resolved
/// removed. Any other command has no projection and keeps its own bytes,
/// as does a call with its own `cwd` argument: the pass reads that call
/// from the directory the argument names, and the sink settles the
/// directory before it projects the text.
pub(super) fn projected_input(
    original: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
) -> Option<Map<String, Value>> {
    if original.contains_key("cwd") {
        return None;
    }
    let command = original.get("command")?.as_str()?;
    // The pre-tool pass answered with the settled workspace, not the spelling
    // the harness sent. Reading the payload's own `cwd` here would resolve the
    // activation script against `~/project` or a symlinked path the verdict
    // never used, and the route would carry text Guard did not answer for.
    let projected = guard_command::pretool::generic::contained_target(
        command,
        guard_command::pretool::PathContext {
            home_dir: Some(home_dir),
            cwd: Some(workspace),
            ..Default::default()
        },
    )?;
    let mut input = original.clone();
    input.insert("command".to_owned(), Value::String(projected));
    Some(input)
}

/// The call the runtime's own sink is asked about for a call with its own
/// `cwd` argument: the argument written as a leading `cd` into that
/// directory, as the sink settles it, then projected. `None` for any other
/// call, and for an argument the sink refuses, which keeps Guard's own sink.
#[cfg(unix)]
pub(super) fn directory_input(
    original: &Map<String, Value>,
    workspace: &str,
    home_dir: &str,
) -> Option<Map<String, Value>> {
    if !original.contains_key("cwd") {
        return None;
    }
    let changed = crate::contained_workspace_sink::directory_change(
        original,
        std::path::Path::new(workspace),
        std::path::Path::new(home_dir),
    )?;
    Some(projected_input(&changed, workspace, home_dir).unwrap_or(changed))
}

/// Whether `target`, from the workspace, names the workspace root or a
/// sibling repository's root: where Guard's own sink peels a leading `cd`
/// and asks about the rest again, as the native sink's wrapper peel does.
#[cfg(any(target_os = "macos", target_os = "linux", all(unix, test)))]
pub(super) fn project_root(workspace: &str, home: &str, target: &str) -> bool {
    let (Ok(root), Ok(directory)) = (
        std::fs::canonicalize(workspace),
        std::fs::canonicalize(std::path::Path::new(workspace).join(target)),
    ) else {
        return false;
    };
    if !directory.is_dir() {
        return false;
    }
    let Some(query) = directory.to_str() else {
        return false;
    };
    directory == root
        || guard_command::pretool::contained_wrapper_plan(
            "",
            workspace,
            None,
            Some(home),
            Some(query),
        )
        .project_root
        .and_then(|sibling| std::fs::canonicalize(sibling).ok())
            == Some(directory)
}

#[cfg(not(unix))]
pub(super) fn directory_input(
    _original: &Map<String, Value>,
    _workspace: &str,
    _home_dir: &str,
) -> Option<Map<String, Value>> {
    None
}
