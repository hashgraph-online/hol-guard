//! Commands that name something outside the workspace. The sandbox would
//! refuse the effect, but a command aimed at home, credentials, Guard's own
//! state or another directory is not workspace work: it keeps the review or
//! denial the evaluator gives it instead of failing quietly in the sandbox.

use crate::CommandSegmentV1;
use std::path::{Component, Path};

/// Guard's own command line manages state outside any workspace.
const GUARD_CLIS: &[&str] = &["hol-guard", "guard"];

/// Devices every sandbox profile offers.
const DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/tty",
];

pub(super) fn reaches_outside(segment: &CommandSegmentV1, name: &str, workspace: &Path) -> bool {
    if GUARD_CLIS.contains(&name) {
        return true;
    }
    // A variable or home path the sandbox would resolve differently. Redirect
    // targets appear only in the segment text.
    if expands_variable(&segment.text, name)
        || segment.text.split_whitespace().any(|word| {
            word.trim_start_matches(['>', '<', '&', '|', '"', '\'', '='])
                .starts_with('~')
        })
    {
        return true;
    }
    if redirect_targets(&segment.text).any(|target| outside(target, name, workspace)) {
        return true;
    }
    segment.arguments.iter().any(|argument| {
        let value = match argument.split_once('=') {
            Some((option, value)) if option.starts_with('-') => value,
            _ if argument.starts_with('-') => return false,
            _ => argument.as_str(),
        };
        outside(value, name, workspace)
    })
}

/// Text tools whose programs use `$` as an anchor or a field reference.
const PATTERN_TOOLS: &[&str] = &[
    "awk", "gawk", "mawk", "nawk", "sed", "grep", "egrep", "fgrep", "rg", "jq",
];

/// A `$` the shell expands. Inside single quotes it is literal, and a pattern
/// tool reads it as program text (`awk '/x$/{f=1}'`). Any other tool may hand
/// its arguments to a shell or expand them itself, so every `$` counts there.
fn expands_variable(text: &str, name: &str) -> bool {
    if !PATTERN_TOOLS.contains(&name) {
        return text.contains('$');
    }
    let mut single = false;
    let mut double = false;
    let mut escaped = false;
    for current in text.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match current {
            '\\' if !single => escaped = true,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '$' if !single => return true,
            _ => {}
        }
    }
    false
}

/// Redirect targets live only in the segment text: `> out`, `2>>log`, `&>x`.
pub(super) fn redirect_targets(text: &str) -> impl Iterator<Item = &str> {
    let mut words = text.split_whitespace().peekable();
    std::iter::from_fn(move || {
        while let Some(word) = words.next() {
            let operator = word.trim_start_matches(|c: char| c.is_ascii_digit() || c == '&');
            if !operator.starts_with(['>', '<']) {
                continue;
            }
            let target = operator.trim_start_matches(['>', '<', '|', '&']);
            let target = if target.is_empty() {
                words.next().unwrap_or_default()
            } else {
                target
            };
            return Some(target.trim_matches(['"', '\'']));
        }
        None
    })
}

pub(super) fn outside(value: &str, name: &str, workspace: &Path) -> bool {
    let path = Path::new(value);
    if value.starts_with('~') {
        return true;
    }
    // Git metadata belongs to `git`; another tool writing hooks or config
    // there is the attack the write-denied paths stand for.
    if name != "git"
        && path
            .components()
            .any(|component| component.as_os_str() == ".git")
    {
        return true;
    }
    if path.is_absolute() {
        // Only a path whose top directory exists names the file system; a
        // pattern such as `/api/v1` does not.
        let top = path.components().nth(1);
        let names_file_system =
            top.is_some_and(|top| Path::new("/").join(top.as_os_str()).exists());
        return names_file_system && !path.starts_with(workspace) && !DEVICES.contains(&value);
    }
    let mut depth = 0usize;
    path.components().any(|component| match component {
        Component::ParentDir => match depth.checked_sub(1) {
            Some(up) => {
                depth = up;
                false
            }
            None => true,
        },
        Component::Normal(_) => {
            depth += 1;
            false
        }
        _ => false,
    })
}
