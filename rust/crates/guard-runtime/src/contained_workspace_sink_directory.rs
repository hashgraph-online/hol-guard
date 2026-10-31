//! The directory an Oh My Pi `bash` call asks to run in.
//!
//! Oh My Pi's `bash` tool takes an optional `cwd` argument and runs the
//! command there. Native authority resolves it the way the host does before
//! judging the command, so the contained run starts in that directory too.
//! Guard's own sink asks again with that directory as the session folder and,
//! when the answer is the same workspace sandbox, runs the call there. Any
//! other call has the argument written as a leading `cd '<directory>' &&`,
//! which the wrapper peel resolves, rebases onto a sibling repository and
//! authorizes again. This replays those steps, except that the sandbox is
//! never rooted below the workspace: the protected-path and Git write
//! denials are built from the root, so a call running in `.git` or a
//! harness folder takes the `cd` form, which keeps the workspace root.

use super::*;

/// Input spellings other hosts use. A call carrying one is not an Oh My Pi
/// call, so its `cwd` argument is not read.
const OTHER_INPUT_KEYS: [&str; 2] = ["toolInput", "arguments"];

/// Run the call `receipt` authorized for `payload`, which names its own
/// `cwd`, from that directory.
pub(super) fn contained(
    payload: &Map<String, Value>,
    workspace: &Path,
    authority: &Authority<'_>,
    receipt: &Map<String, Value>,
    signals: &process::Signals,
) -> Outcome<i32> {
    if !wrapper::contained_receipt(receipt) {
        return Err(Failure::unauthorized());
    }
    let home = authority.arguments.home.as_path();
    if OTHER_INPUT_KEYS
        .iter()
        .any(|key| payload.contains_key(*key))
    {
        return Err(rejected());
    }
    let input = payload
        .get("tool_input")
        .and_then(Value::as_object)
        .ok_or_else(rejected)?;
    let (directory, rest) = split(input, workspace, home).ok_or_else(rejected)?;
    if workspace_sandbox(receipt) {
        // The `cd` form is judged from the session folder and can lose the
        // workspace sandbox native authority chose inside `cwd`. Only a
        // directory the sandbox may be rooted at is asked about: the
        // workspace itself, or a sibling repository's own root. The call
        // then runs through the wrapper from there, so a trailing group or
        // a virtualenv activation is projected as the pre-tool pass did.
        let root = directory.clone().unwrap_or_else(|| workspace.to_path_buf());
        if rootable(&root, workspace, home) {
            let mut rooted = payload.clone();
            rooted.insert("cwd".to_owned(), Value::String(path_text(&root)?));
            rooted.insert("tool_input".to_owned(), Value::Object(rest.clone()));
            if let Some(first) = authority.authorize(&rooted).filter(workspace_sandbox) {
                return wrapper::contained(&rooted, &root, authority, &first, signals);
            }
        }
    }
    let changed_input = with_directory(directory.as_deref(), rest).ok_or_else(rejected)?;
    let mut changed = payload.clone();
    changed.insert("tool_input".to_owned(), Value::Object(changed_input));
    let receipt = authority
        .authorize(&changed)
        .ok_or_else(Failure::unauthorized)?;
    wrapper::contained(&changed, workspace, authority, &receipt, signals)
}

/// `input` with its `cwd` argument written as a leading `cd`, as the sink
/// runs it, or `None` for an argument the sink refuses.
pub(crate) fn directory_change(
    input: &Map<String, Value>,
    workspace: &Path,
    home: &Path,
) -> Option<Map<String, Value>> {
    let (directory, rest) = split(input, workspace, home)?;
    with_directory(directory.as_deref(), rest)
}

fn workspace_sandbox(receipt: &Map<String, Value>) -> bool {
    receipt_matches(receipt) && !host_split(receipt.get("reason"))
}

/// The directory `input`'s `cwd` argument names, and the input without it.
fn split(
    input: &Map<String, Value>,
    workspace: &Path,
    home: &Path,
) -> Option<(Option<PathBuf>, Map<String, Value>)> {
    input.get("command")?.as_str()?;
    let directory = requested(input.get("cwd")?, workspace, home)?;
    let mut rest = input.clone();
    rest.remove("cwd");
    Some((directory, rest))
}

/// The canonical directory `value` names: `Some(None)` for the session
/// directory, `None` for a value the sink refuses.
///
/// An empty value or a root of only slashes keeps the session directory, as
/// on the host. `~` and `~/x` expand to home and any other text is joined to
/// the session directory. Forms the host rewrites before resolving (`@` and
/// `:` prefixes, `file:` and other URLs, non-ASCII text, backslashes) are
/// refused, as native authority sends them to review.
fn requested(value: &Value, workspace: &Path, home: &Path) -> Option<Option<PathBuf>> {
    let value = value.as_str()?;
    if value.chars().all(|character| character == '/') {
        return Some(None);
    }
    if !value.is_ascii()
        || value
            .chars()
            .any(|character| character < ' ' || matches!(character, '\x7f' | '\\'))
        || value.starts_with(['@', ':'])
        || value.starts_with("file:")
        || value.contains("://")
    {
        return None;
    }
    let path = if let Some(rest) = value.strip_prefix('~') {
        if !rest.is_empty() && !rest.starts_with('/') {
            return None;
        }
        home.join(rest.trim_start_matches('/'))
    } else {
        workspace.join(value)
    };
    let directory = std::fs::canonicalize(path).ok()?;
    let root = std::fs::canonicalize(workspace).ok()?;
    if !directory.is_dir() {
        return None;
    }
    Some((directory != root).then_some(directory))
}

/// Whether the sandbox may be rooted at `root`: the workspace itself, or
/// the root of a sibling repository. A directory below the workspace is
/// never a root, so its `.git` and harness folders stay protected, and a
/// path through a `.git` folder is refused outright.
fn rootable(root: &Path, workspace: &Path, home: &Path) -> bool {
    if root
        .components()
        .any(|component| component.as_os_str() == ".git")
    {
        return false;
    }
    let sibling = || {
        let plan = guard_command::pretool::contained_wrapper_plan(
            "",
            workspace.to_str()?,
            None,
            Some(home.to_str()?),
            Some(root.to_str()?),
        );
        std::fs::canonicalize(plan.project_root?).ok()
    };
    std::fs::canonicalize(workspace).is_ok_and(|workspace| root == workspace)
        || sibling().as_deref() == Some(root)
}

fn with_directory(
    directory: Option<&Path>,
    mut rest: Map<String, Value>,
) -> Option<Map<String, Value>> {
    if let (Some(directory), Some(Value::String(command))) = (directory, rest.get_mut("command")) {
        let quoted = crate::mcp_proxy_shlex::quote(directory.to_str()?);
        *command = format!("cd {quoted} && {command}");
    }
    Some(rest)
}

fn rejected() -> Failure {
    Failure::new(
        "contained_run_authorization_failed",
        "Guard could not resolve the directory this command runs in.",
    )
}

#[cfg(test)]
#[path = "contained_workspace_sink_directory_tests.rs"]
mod tests;
