//! Commands that name something outside the workspace. The sandbox would
//! refuse the effect, but a command aimed at home, credentials, Guard's own
//! state or another directory is not workspace work: it keeps the review or
//! denial the evaluator gives it instead of failing quietly in the sandbox.

use crate::CommandSegmentV1;
use std::path::{Component, Path};

/// Guard's own command line manages state outside any workspace.
const GUARD_CLIS: &[&str] = &["hol-guard", "guard"];

/// Database clients change a server outside any workspace, even over a local
/// socket: `psql -c 'drop table t'` is no workspace work the sandbox could keep.
const DATABASE_CLIENTS: &[&str] = &[
    "psql",
    "pg_dump",
    "pg_dumpall",
    "pg_restore",
    "mysql",
    "mariadb",
    "mysqldump",
    "sqlcmd",
    "redis-cli",
    "mongo",
    "mongosh",
    "cqlsh",
];

/// Guard's safety guide, which its managed agent instructions tell agents to
/// read first. The sandbox launcher copies this one file into the private home
/// the sandboxed shell sees, so the unquoted literal expands to the same text
/// there. Any other home path, including one that walks out of
/// `.hol-support`, still reaches outside.
const SAFETY_GUIDE: &str = "~/.hol-support/SAFETY.md";

/// Programs that only print the guide they are given.
const GUIDE_READERS: &[&str] = &["cat", "head", "tail", "sed", "nl", "wc"];

/// Devices every sandbox profile offers.
const DEVICES: &[&str] = &[
    "/dev/null",
    "/dev/stdin",
    "/dev/stdout",
    "/dev/stderr",
    "/dev/tty",
];

/// `temp_fixed` says nothing in the command rebinds `TMPDIR`, so each
/// `$TMPDIR` the shell expands is the one the sandbox launcher sets.
/// `home_fixed` says nothing in the command rebinds `HOME`, so `~` is the
/// private home the launcher seeds with the safety guide.
/// `granted_script` is the operand of an outside script the sandbox may read.
pub(super) fn reaches_outside(
    segment: &CommandSegmentV1,
    name: &str,
    workspace: &Path,
    temp_fixed: bool,
    home_fixed: bool,
    granted_script: Option<&str>,
) -> bool {
    if GUARD_CLIS.contains(&name) || DATABASE_CLIENTS.contains(&name) {
        return true;
    }
    // A variable or home path the sandbox would resolve differently. Redirect
    // targets appear only in the segment text.
    let fixed_expansions = identity_expansions_only(segment, name)
        || exit_status_expansions_only(&segment.text)
        || (temp_fixed && private_temp_expansions_only(&segment.text));
    let guide = home_fixed && GUIDE_READERS.contains(&name);
    if (expands_variable(&segment.text, name) && !fixed_expansions)
        || segment.text.split_whitespace().any(|word| {
            // Only the bare word expands; a quoted or redirected guide does not.
            !(guide && word == SAFETY_GUIDE)
                && word
                    .trim_start_matches(['>', '<', '&', '|', '"', '\'', '='])
                    .starts_with('~')
        })
    {
        return true;
    }
    if redirect_targets(&segment.text).any(|target| outside(target, name, workspace)) {
        return true;
    }
    segment.arguments.iter().any(|argument| {
        if granted_script == Some(argument.as_str()) || (guide && argument == SAFETY_GUIDE) {
            return false;
        }
        let value = match argument.split_once('=') {
            Some((option, value)) if option.starts_with('-') => value,
            _ if argument.starts_with('-') => return false,
            _ => argument.as_str(),
        };
        outside(value, name, workspace)
    })
}

/// Commit identity settings. Git records their values in the commit it writes
/// and starts nothing by them.
const IDENTITY_KEYS: &[&str] = &[
    "user.name",
    "user.email",
    "author.name",
    "author.email",
    "committer.name",
    "committer.email",
];

/// Whether every `$` in a Git segment is a double-quoted variable that sets a
/// `-c` commit identity before the subcommand, as in
/// `git -c user.name="${USER:-dev}" commit`. The quotes keep the expansion
/// one word, and Git only writes it into the commit, so it names no path the
/// sandbox would resolve differently. Any other key, an unquoted or
/// command-substituting expansion, or a `$` anywhere else keeps the refusal.
fn identity_expansions_only(segment: &CommandSegmentV1, name: &str) -> bool {
    if name != "git" || segment.text.contains('`') {
        return false;
    }
    // Every `$` in the text must expand, so a single-quoted or escaped one in
    // an identity value cannot stand in for an expansion elsewhere, such as a
    // redirect target.
    let Some(expansions) = quoted_expansions(&segment.text)
        .filter(|expansions| *expansions == segment.text.matches('$').count())
    else {
        return false;
    };
    let mut identity = 0usize;
    let mut global = true;
    let mut arguments = segment.arguments.iter();
    while let Some(argument) = arguments.next() {
        if global && argument == "-c" {
            let Some(setting) = arguments.next() else {
                return false;
            };
            if setting.contains('$') {
                let key = setting
                    .split_once('=')
                    .map(|(key, _)| key.to_ascii_lowercase());
                if !key.is_some_and(|key| IDENTITY_KEYS.contains(&key.as_str())) {
                    return false;
                }
                identity += setting.matches('$').count();
            }
            continue;
        }
        global &= argument.starts_with('-');
        if argument.contains('$') {
            return false;
        }
    }
    expansions > 0 && expansions == identity
}

/// `${TMPDIR:-/tmp}` without its `$`.
pub(in crate::pretool) const PRIVATE_TEMP_WITH_FALLBACK: &str = "{TMPDIR:-/tmp}";

/// Whether every `$` in `text` is a `$TMPDIR`, `${TMPDIR}` or
/// `${TMPDIR:-/tmp}` the shell expands. The sandbox launches its shell with
/// `TMPDIR` set to the run's private temporary directory, so such a path
/// names the sandbox's own scratch space rather than a host directory, and
/// the `/tmp` fallback is never used there.
pub(in crate::pretool) fn private_temp_expansions_only(text: &str) -> bool {
    let characters: Vec<char> = text.chars().collect();
    let (mut single, mut double, mut count, mut index) = (false, false, 0usize, 0usize);
    while let Some(&current) = characters.get(index) {
        index += 1;
        match current {
            '\\' if !single => index += 1,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '`' if !single => return false,
            '$' if !single => {
                let rest: String = characters[index..].iter().take(14).collect();
                let length = if rest.starts_with(PRIVATE_TEMP_WITH_FALLBACK) {
                    PRIVATE_TEMP_WITH_FALLBACK.len()
                } else if rest.starts_with("{TMPDIR}") {
                    8
                } else if rest.starts_with("TMPDIR")
                    && !rest
                        .chars()
                        .nth(6)
                        .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                {
                    6
                } else {
                    return false;
                };
                index += length;
                count += 1;
            }
            _ => {}
        }
    }
    count > 0 && count == text.matches('$').count()
}

/// Whether every `$` in `text` is a `$?` the shell expands. The previous
/// step's exit status is a decimal number, so it names no path the sandbox
/// would resolve differently, as in `test -d out; printf 'out=%s\n' "$?"`.
fn exit_status_expansions_only(text: &str) -> bool {
    let characters: Vec<char> = text.chars().collect();
    let (mut single, mut double, mut count, mut index) = (false, false, 0usize, 0usize);
    while let Some(&current) = characters.get(index) {
        index += 1;
        match current {
            '\\' if !single => index += 1,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '`' if !single => return false,
            '$' if !single => {
                if characters.get(index) != Some(&'?') {
                    return false;
                }
                index += 1;
                count += 1;
            }
            _ => {}
        }
    }
    count > 0 && count == text.matches('$').count()
}

/// Whether `text` names `TMPDIR` anywhere other than in a `$TMPDIR` or
/// `${TMPDIR}` expansion, as an assignment, `export` or `unset` would.
pub(in crate::pretool) fn rebinds_private_temp(text: &str) -> bool {
    text.match_indices("TMPDIR")
        .any(|(at, _)| !(text[..at].ends_with('$') || text[..at].ends_with("${")))
}

/// The number of `$` expansions the shell performs in `text` when each is a
/// plain `$NAME`, `${NAME}`, `${NAME-word}` or `${NAME:-word}` with a literal
/// word, inside double quotes; `None` for any other expansion.
fn quoted_expansions(text: &str) -> Option<usize> {
    let characters: Vec<char> = text.chars().collect();
    let (mut single, mut double, mut count, mut index) = (false, false, 0usize, 0usize);
    while let Some(&current) = characters.get(index) {
        index += 1;
        match current {
            '\\' if !single => index += 1,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            '$' if !single => {
                if !double {
                    return None;
                }
                index = expansion_end(&characters, index)?;
                count += 1;
            }
            _ => {}
        }
    }
    Some(count)
}

/// The index after a variable expansion whose name starts at `start`.
fn expansion_end(characters: &[char], start: usize) -> Option<usize> {
    let braced = characters.get(start) == Some(&'{');
    let mut index = start + usize::from(braced);
    let name_start = index;
    while characters
        .get(index)
        .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
    {
        index += 1;
    }
    if index == name_start || characters[name_start].is_ascii_digit() {
        return None;
    }
    if !braced {
        return Some(index);
    }
    if characters.get(index) == Some(&':') {
        index += 1;
        if characters.get(index) != Some(&'-') {
            return None;
        }
    }
    if characters.get(index) == Some(&'-') {
        index += 1;
        while characters
            .get(index)
            .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(*c, '.' | '_' | '@' | '+' | '-'))
        {
            index += 1;
        }
    }
    (characters.get(index) == Some(&'}')).then_some(index + 1)
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

#[cfg(test)]
#[path = "workspace_contained_identity_tests.rs"]
mod identity_tests;
