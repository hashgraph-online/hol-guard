//! Whether Grok's hook files and event configurations carry Guard's hooks,
//! which `cli/native_install_checks.py` decided before it moved here.

use std::path::Path;

use super::grok_hook_command::{Checker, Owner};
use super::Ctx;
use crate::native_install_verdict::Runner;
use crate::pyjson::{self, PyVal};

/// Events the prompt hook file must cover.
const PROMPT_EVENTS: [&str; 3] = ["UserPromptSubmit", "SubagentStart", "SessionStart"];

/// The hook file's JSON object, when it is a file holding one.
fn read_hooks(ctx: &Ctx, path: &Path) -> Option<PyVal> {
    let path = ctx.absolute(path);
    if !path.is_file() {
        return None;
    }
    let text = String::from_utf8(std::fs::read(path).ok()?).ok()?;
    let payload = pyjson::parse(&text).ok()?;
    let hooks = payload.get("hooks")?.clone();
    hooks.as_dict()?;
    Some(hooks)
}

fn is_command(hook: &PyVal) -> Option<&str> {
    match (hook.get("type"), hook.get("command")) {
        (Some(PyVal::Str(kind)), Some(PyVal::Str(command))) if kind == "command" => Some(command),
        _ => None,
    }
}

/// One managed catch-all `PreToolUse` entry running one Guard command hook.
pub(super) fn pretool_is_catchall<R: Runner>(
    checker: &mut Checker<'_, R>,
    ctx: &Ctx,
    path: &Path,
    owner: Option<&Owner<'_>>,
) -> bool {
    let Some(hooks) = read_hooks(ctx, path) else {
        return false;
    };
    let Some([entry]) = hooks.get("PreToolUse").and_then(PyVal::as_list) else {
        return false;
    };
    let catchall = match entry.get("matcher") {
        None | Some(PyVal::Null) => true,
        Some(PyVal::Str(matcher)) => matcher.is_empty(),
        Some(_) => false,
    };
    if entry.as_dict().is_none() || !catchall {
        return false;
    }
    let Some([hook]) = entry.get("hooks").and_then(PyVal::as_list) else {
        return false;
    };
    hook.as_dict().is_some()
        && is_command(hook).is_some_and(|command| checker.recognizes(command, owner))
}

/// The prompt gate and the passive lifecycle callbacks all have Guard hooks.
pub(super) fn prompt_is_observe<R: Runner>(
    checker: &mut Checker<'_, R>,
    ctx: &Ctx,
    path: &Path,
    owner: Option<&Owner<'_>>,
) -> bool {
    let Some(hooks) = read_hooks(ctx, path) else {
        return false;
    };
    PROMPT_EVENTS
        .iter()
        .all(|event| event_has_hook(checker, hooks.get(event), owner))
}

/// A valid Guard command hook somewhere in a native event configuration.
pub(super) fn event_has_hook<R: Runner>(
    checker: &mut Checker<'_, R>,
    entries: Option<&PyVal>,
    owner: Option<&Owner<'_>>,
) -> bool {
    let Some(entries) = entries
        .and_then(PyVal::as_list)
        .filter(|list| !list.is_empty())
    else {
        return false;
    };
    entries
        .iter()
        .filter_map(|entry| entry.get("hooks").and_then(PyVal::as_list))
        .flatten()
        .filter(|hook| hook.as_dict().is_some())
        .filter_map(is_command)
        .any(|command| checker.recognizes(command, owner))
}

/// `event_has_hook` over only the entries with no matcher, as the managed
/// config's backup hooks must be catch-alls. Anything but a list is false.
pub(super) fn event_has_catchall_hook<R: Runner>(
    checker: &mut Checker<'_, R>,
    entries: &PyVal,
    owner: Option<&Owner<'_>>,
) -> bool {
    let Some(list) = entries.as_list() else {
        return false;
    };
    let catchall = PyVal::List(
        list.iter()
            .filter(|entry| {
                entry.as_dict().is_some() && !entry.get("matcher").is_some_and(PyVal::truthy)
            })
            .cloned()
            .collect(),
    );
    event_has_hook(checker, Some(&catchall), owner)
}
