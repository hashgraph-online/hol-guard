//! Which read-only run a command is, read the way Guard's own sink reads it.
//!
//! The sink peels the settings and launchers in front of the program, asks
//! native authority which kind of run the program is, and for a package
//! manager's own test script reads the script into the runner words it
//! spells. This replays that reading for the plain shape.

use super::*;

/// The kind of read-only run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Eval,
    Vitest,
    NodeTest,
    Git,
    Pytest,
    NodeTool,
    /// A package manager's own test script, run as the runner it names.
    Package,
}

/// The program a read-only run starts, the seconds a system `timeout` in
/// front of it allows, and its kind.
pub(crate) type Program = (Vec<String>, Option<u64>, Kind);

/// The program a plain read-only run starts, the seconds a system `timeout`
/// in front of it allows, and its kind, read with the operations Guard's
/// own sink reads it with. `None` for anything else: a setting, carried or
/// dropped, or a program of another kind.
pub(crate) fn plain_program(command: &str) -> Option<Program> {
    if !one_command(command) {
        return None;
    }
    let words = strings(native("command_words", json!({ "command_text": command })).ok()?)?;
    let peeled = native(
        "command_prefix_split",
        json!({ "command": words, "drop_data": true }),
    )
    .ok()?;
    if peeled.get("assignments") != Some(&json!([]))
        || peeled.get("dropped_data") != Some(&Value::Bool(false))
    {
        return None;
    }
    let split = native(
        "command_prefix_split",
        json!({ "command": words, "drop_data": false }),
    )
    .ok()?;
    let index = usize::try_from(split.get("core_index")?.as_u64()?).ok()?;
    let core = words.get(index..)?.to_vec();
    let peeled = native("run_prefix_peel", json!({ "command": core })).ok()?;
    let core = strings(peeled.get("core")?.clone())?;
    let seconds = match peeled.get("seconds")? {
        Value::Null => None,
        seconds => Some(seconds.as_u64()?),
    };
    let kind = kind(&core)?;
    Some((core, seconds, kind))
}

/// Whether the shell reads `command` as one simple command: a single
/// segment with no word that redirects it or joins another. Any other
/// program is planned as pytest, so a chain such as `cd x && python3 -c 0`
/// must never reach the planner as one argv.
fn one_command(command: &str) -> bool {
    let request = guard_command::CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "guard-shell".into(),
    };
    guard_command::parse_command(&request).is_ok_and(|model| match model.segments.as_slice() {
        [segment] => !segment.tokens.iter().any(|token| {
            token
                .trim_start_matches(|character: char| character.is_ascii_digit())
                .starts_with(['<', '>', '&', '|', ';'])
        }),
        _ => false,
    })
}

/// The settings an inert prefix carries into a read-only run, and the
/// command behind them, which must itself be a plain read-only run.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Carried {
    pub(crate) settings: Vec<(String, String)>,
    pub(crate) behind: Vec<String>,
}

/// The program a read-only run starts behind settings in front of it, read
/// as Guard's own sink reads it: inert settings such as `CI=1` are carried
/// into the run's environment, a plain-data setting is dropped, and the
/// command behind them is read again as a plain run. `None` for a command
/// with no setting in front, or whose remainder is not a plain read-only run.
pub(crate) fn carried_program(command: &str) -> Option<(Carried, Program)> {
    let words = strings(native("command_words", json!({ "command_text": command })).ok()?)?;
    let peeled = native(
        "command_prefix_split",
        json!({ "command": words, "drop_data": true }),
    )
    .ok()?;
    let settings: Vec<(String, String)> =
        serde_json::from_value(peeled.get("assignments")?.clone()).ok()?;
    let dropped = peeled.get("dropped_data")?.as_bool()?;
    if settings.is_empty() && !dropped {
        return None;
    }
    let index = usize::try_from(peeled.get("core_index")?.as_u64()?).ok()?;
    let behind = words
        .get(index..)
        .filter(|behind| !behind.is_empty())?
        .to_vec();
    let program = plain_program(&crate::mcp_proxy_shlex::join(&behind))?;
    Some((Carried { settings, behind }, program))
}

/// The kind of run `core` is, as native authority reads it.
pub(super) fn kind(core: &[String]) -> Option<Kind> {
    let kinds = native("contained_kind", json!({ "command": core })).ok()?;
    let kind = |name: &str| kinds.get(name).and_then(Value::as_bool);
    if kind("package_test")? {
        return Some(Kind::Package);
    }
    // Guard's own sink takes the first kind in this order, and plans any
    // other program as pytest.
    Some(
        match (
            kind("inline_eval")?,
            kind("node_tool")?,
            kind("git")?,
            kind("vitest")?,
            kind("node_test")?,
        ) {
            (true, ..) => Kind::Eval,
            (false, true, ..) => Kind::NodeTool,
            (false, false, true, ..) => Kind::Git,
            (false, false, false, true, _) => Kind::Vitest,
            (false, false, false, false, true) => Kind::NodeTest,
            (false, false, false, false, false) => Kind::Pytest,
        },
    )
}

/// The runner words a package manager's own test script spells, read from
/// the nearest manifest under `workspace`, and their kind: only a Node test
/// or Vitest run, the runners such a script may name.
pub(super) fn package_test(argv: &[String], workspace: &Path) -> Outcome<(Vec<String>, Kind)> {
    let workspace = path_text(workspace)?;
    let words = native(
        "package_test_command",
        json!({ "command": argv, "workspace": workspace, "cwd": workspace }),
    )?;
    let words = strings(words).ok_or_else(|| unavailable("invalid_reply"))?;
    match kind(&words) {
        Some(kind @ (Kind::NodeTest | Kind::Vitest)) => Ok((words, kind)),
        _ => Err(Failure::unauthorized()),
    }
}

pub(super) fn strings(value: Value) -> Option<Vec<String>> {
    serde_json::from_value(value).ok()
}

#[cfg(test)]
#[path = "contained_readonly_program_tests.rs"]
mod tests;
