//! A call whose core sits behind a wrapper: a leading `cd`, a trailing
//! `2>&1`, an output filter chain or a `; echo "<label>$?"` status echo.
//!
//! Guard's own sink asks native authority to peel the wrapper, then: a
//! wrapper it refuses runs whole, and only in the workspace sandbox; a
//! peeled call must carry a contained receipt, and runs from the root of
//! the workspace or of the sibling repository its directory lies in. When
//! that directory is below the root and the receipt is the workspace
//! sandbox's, the sandbox runs the text whole from the root. Otherwise the
//! core is asked about again from its directory and run with its output
//! redirected and filtered as the wrapper spells, and the echo prints the
//! status the shell would have. A call's own `cwd` argument is settled first
//! (`directory`), then a trailing group or a virtualenv activation is
//! projected, as the pre-tool pass projected it. This replays those
//! steps for a core run from the root itself; Guard's own sink also runs a
//! read-only core from below it, which the edge keeps there.

use guard_command::pretool::{contained_wrapper_plan, ContainedOutput, ContainedWrapperCore};

use super::*;

/// What native authority's peel says of a call.
enum Peel {
    /// Nothing is wrapped.
    Bare,
    /// A wrapper the sink does not peel.
    Refused,
    Wrapped(ContainedWrapperCore),
}

/// Run the call `receipt` authorized for `payload` from `workspace`.
pub(super) fn contained(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    receipt: &Map<String, Value>,
    signals: &process::Signals,
) -> Outcome<i32> {
    let input = payload.get("tool_input").and_then(Value::as_object);
    if input.is_some_and(|input| input.contains_key("cwd")) {
        return directory::contained(payload, workspace, authority, receipt, signals);
    }
    if let Some(projected) = projected(payload, workspace, &authority.arguments.home) {
        // A trailing group runs the list inside it, and a virtualenv
        // activation hands its verdict to the command after it, so the
        // pre-tool pass answered for that command. The call as issued must
        // carry the receipt; the projected text is then asked about on its
        // own and run as that call.
        if !contained_receipt(receipt) {
            return Err(Failure::unauthorized());
        }
        let asked = with_text(payload, &projected);
        let receipt = authority
            .authorize(&asked)
            .ok_or_else(Failure::unauthorized)?;
        return contained(&asked, workspace, authority, &receipt, signals);
    }
    match peel(payload, workspace, &authority.arguments.home) {
        Peel::Wrapped(peeled) => wrapped(payload, workspace, authority, receipt, peeled, signals),
        Peel::Refused if !receipt_matches(receipt) => Err(Failure::unauthorized()),
        Peel::Bare | Peel::Refused => plain(payload, workspace, authority, receipt, signals),
    }
}

/// The command a trailing group or a virtualenv activation in `payload`
/// projects to, read from `workspace` as the pre-tool pass reads it.
fn projected(payload: &Map<String, Value>, workspace: &Path, home: &Path) -> Option<String> {
    let input = payload.get("tool_input")?.as_object()?;
    let context = guard_command::pretool::PathContext {
        home_dir: Some(home.to_str()?),
        cwd: Some(workspace.to_str()?),
        ..Default::default()
    };
    guard_command::pretool::generic::contained_target(input.get("command")?.as_str()?, context)
}

/// `payload` with `command` in place of its own text.
fn with_text(payload: &Map<String, Value>, command: &str) -> Map<String, Value> {
    let mut asked = payload.clone();
    if let Some(Value::Object(input)) = asked.get_mut("tool_input") {
        input.insert("command".to_owned(), Value::String(command.to_owned()));
    }
    asked
}

fn peel(payload: &Map<String, Value>, workspace: &Path, home: &Path) -> Peel {
    let Some(command) = payload
        .get("tool_input")
        .and_then(|input| input.get("command"))
        .and_then(Value::as_str)
    else {
        return Peel::Bare;
    };
    let (Some(workspace), Some(home)) = (workspace.to_str(), home.to_str()) else {
        return Peel::Refused;
    };
    let plan = contained_wrapper_plan(command, workspace, None, Some(home), None);
    match (plan.refusal, plan.plan) {
        (Some(_), _) => Peel::Refused,
        (None, Some(peeled)) => Peel::Wrapped(peeled),
        (None, None) => Peel::Bare,
    }
}

/// A call with nothing peeled: a read-only run, or the workspace sandbox
/// from the workspace or the sibling repository it is anchored in.
fn plain(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    receipt: &Map<String, Value>,
    signals: &process::Signals,
) -> Outcome<i32> {
    if let Some(route) = readonly::readonly_route(receipt) {
        return readonly::run(payload, workspace, authority, route, signals);
    }
    if !receipt_matches(receipt) || host_split(receipt.get("reason")) {
        return Err(Failure::unauthorized());
    }
    let root = sibling_root(payload, &authority.workspace, &authority.arguments.home);
    let root = root.unwrap_or_else(|| workspace.to_path_buf());
    run_workspace_contained(payload, &root, authority, receipt, signals)
}

fn wrapped(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    receipt: &Map<String, Value>,
    peeled: ContainedWrapperCore,
    signals: &process::Signals,
) -> Outcome<i32> {
    if !contained_receipt(receipt) {
        return Err(Failure::unauthorized());
    }
    let home = authority.arguments.home.to_str();
    let (root, at_root) = home
        .and_then(|home| rooted(&peeled.directory, workspace, home))
        .ok_or_else(Failure::unauthorized)?;
    if !at_root {
        // The workspace sandbox starts only at its root, where the resident
        // classified the whole text, so the `cd` runs inside it as issued.
        if receipt_matches(receipt) && !host_split(receipt.get("reason")) {
            return run_workspace_contained(payload, &root, authority, receipt, signals);
        }
        return Err(Failure::unauthorized());
    }
    let asked = with_core(payload, &peeled.core, &path_text(&peeled.directory)?);
    bounded(peeled.output.as_ref(), signals, || {
        let receipt = authority
            .authorize(&asked)
            .ok_or_else(Failure::unauthorized)?;
        contained(&asked, &root, authority, &receipt, signals)
    })
}

/// Whether `receipt` sends the call to any contained profile.
pub(super) fn contained_receipt(receipt: &Map<String, Value>) -> bool {
    let text = |name: &str| receipt.get(name).and_then(Value::as_str);
    text("decision") == Some("deny")
        && text("policy_action") == Some("sandbox-required")
        && text("required_execution_profile").is_some()
        && receipt.get("observe_mode") != Some(&Value::Bool(true))
}

/// The root a peeled `directory` runs from, and whether it is that root as
/// spelled: the workspace when the directory lies in it, else the root of
/// the sibling repository holding it. `None` when it is in neither.
fn rooted(directory: &Path, workspace: &Path, home: &str) -> Option<(PathBuf, bool)> {
    let inside = std::fs::canonicalize(workspace).ok()?;
    let resolved = std::fs::canonicalize(directory).ok()?;
    let root = if resolved.starts_with(&inside) {
        inside
    } else {
        let query = directory.to_str()?;
        let plan = contained_wrapper_plan("", workspace.to_str()?, None, Some(home), Some(query));
        std::fs::canonicalize(plan.project_root?).ok()?
    };
    let at_root = directory == root;
    Some((root, at_root))
}

/// `payload` for `core`, asked from `directory`.
fn with_core(payload: &Map<String, Value>, core: &str, directory: &str) -> Map<String, Value> {
    let mut asked = payload.clone();
    let mut tool_input = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    tool_input.insert("command".to_owned(), Value::String(core.to_owned()));
    asked.insert("tool_input".to_owned(), Value::Object(tool_input));
    asked.insert("cwd".to_owned(), Value::String(directory.to_owned()));
    asked
}

/// Run the core with its output redirected and filtered as `output` says,
/// then print the status echo's line. A filter that fails replaces the
/// core's own failure, as it does in Guard's own sink.
fn bounded(
    output: Option<&ContainedOutput>,
    signals: &process::Signals,
    run: impl FnOnce() -> Outcome<i32>,
) -> Outcome<i32> {
    let capture = output.is_some_and(|output| output.kind != "all");
    let merge = output.is_some_and(|output| output.merge_stderr);
    // A core wrapped again is peeled only by Guard's own sink.
    if !signals.output.enter(merge, capture) {
        return Err(Failure::unauthorized());
    }
    let result = run();
    let (captured, cut) = signals.output.leave();
    let chain = match output {
        Some(output) if capture => filters::emit(output, (&captured, cut), &signals.output)?,
        _ => None,
    };
    let exit_code = result?;
    let Some((label, kind)) =
        output.and_then(|output| Some((output.status_label.as_ref()?, output.kind)))
    else {
        return Ok(exit_code);
    };
    signals
        .output
        .out(format!("{label}{}\n", status(kind, exit_code, chain)).as_bytes());
    // The shell's status is the echo's own.
    Ok(0)
}

/// What the echo's `$?` reads: after a chain, its last stage's status; after
/// `head` or `tail`, theirs; otherwise the core's.
fn status(kind: &str, exit_code: i32, chain: Option<i32>) -> i32 {
    match kind {
        "pipe" => chain.unwrap_or(0),
        "head" | "tail" => 0,
        _ => exit_code,
    }
}

/// The command the native sink plans for a read-only call issued from
/// `workspace`: the call itself when nothing is wrapped, or the core of a
/// wrapper it peels, run from the root of the workspace or of a sibling
/// repository. `None` for any other call, which keeps Guard's own sink: a
/// wrapper refused, a directory below a root, a core wrapped again or read
/// through to another command.
pub(super) fn native_core(command: &str, workspace: &str, home: &str) -> Option<String> {
    let workspace = std::fs::canonicalize(workspace).unwrap_or_else(|_| PathBuf::from(workspace));
    let plan = contained_wrapper_plan(command, workspace.to_str()?, None, Some(home), None);
    if plan.refusal.is_some() || plan.worktree_add.is_some() {
        return None;
    }
    let Some(peeled) = plan.plan else {
        return Some(command.to_owned());
    };
    let (root, at_root) = rooted(&peeled.directory, &workspace, home)?;
    let root = root.to_str()?;
    let inner = contained_wrapper_plan(&peeled.core, root, None, Some(home), None);
    let context = guard_command::pretool::PathContext {
        home_dir: Some(home),
        cwd: Some(root),
        ..Default::default()
    };
    let projected = guard_command::pretool::generic::contained_target(&peeled.core, context);
    (at_root && inner.refusal.is_none() && inner.plan.is_none() && projected.is_none())
        .then_some(peeled.core)
}

#[cfg(test)]
#[path = "contained_workspace_sink_wrapper_tests.rs"]
mod tests;
