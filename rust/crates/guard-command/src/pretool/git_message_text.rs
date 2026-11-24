//! The message a `git commit`, `git tag`, `git merge` or `git stash push`
//! records. Git stores the value as the text of the object it writes and
//! opens nothing it names, so a credential word in it (`-m "rotate the
//! signing secret"`) describes the change and reads no credential. The
//! whole-command screen sets the message aside the way it sets aside a search
//! pattern; every other token, a `-F` message file, pathspecs and redirect
//! targets included, still meets it.
//!
//! Only a literal message is set aside. A value holding `$` or a backtick can
//! expand into a command or a variable when the shell reads it, so a segment
//! holding one is screened whole.

use crate::CommandSegmentV1;

/// One segment's tokens with its literal Git message values left out, or
/// `None` when it is not a `git` commit, tag, merge or stash push holding one.
pub(super) fn segment_without_messages(segment: &CommandSegmentV1) -> Option<String> {
    let executable = segment.executable.as_deref()?;
    if super::executable_basename(executable) != "git" {
        return None;
    }
    let offset = segment.tokens.len().checked_sub(segment.arguments.len())?;
    if offset == 0 || segment.tokens[offset..] != segment.arguments[..] {
        return None;
    }
    let positions = message_positions(&segment.arguments)?;
    if positions.is_empty() {
        return None;
    }
    Some(
        segment
            .tokens
            .iter()
            .enumerate()
            .filter(|(index, _)| {
                index
                    .checked_sub(offset)
                    .is_none_or(|position| !positions.contains(&position))
            })
            .map(|(_, token)| token.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    )
}

/// Positions in `arguments`, the tokens after `git`, that hold a literal
/// message value. `None` when a message value could expand.
fn message_positions(arguments: &[String]) -> Option<Vec<usize>> {
    let start = super::git_search_text::subcommand_position(arguments)?;
    let mut first = start + 1;
    match arguments[start].as_str() {
        "commit" | "tag" | "merge" => {}
        "stash" if arguments.get(first).map(String::as_str) == Some("push") => first += 1,
        _ => return Some(Vec::new()),
    }
    let mut positions = Vec::new();
    let mut index = first;
    while let Some(argument) = arguments.get(index) {
        let value = argument.as_str();
        if value == "--" {
            break;
        }
        if value == "-m" || value == "--message" {
            if index + 1 < arguments.len() {
                positions.push(index + 1);
            }
            index += 2;
            continue;
        }
        if LONG_OPTIONS_WITH_VALUE.contains(&value) {
            // `--author -m` gives `-m` to `--author`.
            index += 2;
            continue;
        }
        if value.starts_with("--message=") {
            positions.push(index);
        } else if let Some(cluster) = value
            .strip_prefix('-')
            .filter(|rest| !rest.starts_with('-'))
        {
            // `-am "text"` and `-m"text"`: flags that take no value, then `m`.
            if let Some((before, after)) = cluster.split_once('m') {
                if before
                    .chars()
                    .all(|flag| FLAGS_WITHOUT_VALUE.contains(flag))
                {
                    if after.is_empty() {
                        if index + 1 < arguments.len() {
                            positions.push(index + 1);
                        }
                        index += 2;
                        continue;
                    }
                    positions.push(index);
                }
            }
            // `-C -m path` gives `-m` to `-C`: the next token is its value.
            let mut flags = cluster.chars();
            if flags
                .next_back()
                .is_some_and(|last| SHORT_OPTIONS_WITH_VALUE.contains(last))
                && flags.all(|flag| FLAGS_WITHOUT_VALUE.contains(flag))
            {
                index += 2;
                continue;
            }
        }
        index += 1;
    }
    if positions
        .iter()
        .any(|position| arguments[*position].contains(['$', '`']))
    {
        return None;
    }
    Some(positions)
}

/// Short flags of the commit, tag, merge and stash commands that take no
/// value, so a cluster of them can end in `m`.
const FLAGS_WITHOUT_VALUE: &str = "aefnqsv";

/// Short options of those commands that read the next token as their value.
const SHORT_OPTIONS_WITH_VALUE: &str = "CcFtuX";

/// Long options of those commands that read the next token as their value
/// when it is not attached with `=`.
const LONG_OPTIONS_WITH_VALUE: &[&str] = &[
    "--author",
    "--cleanup",
    "--date",
    "--file",
    "--fixup",
    "--into-name",
    "--local-user",
    "--pathspec-from-file",
    "--reedit-message",
    "--reuse-message",
    "--squash",
    "--strategy",
    "--strategy-option",
    "--template",
    "--trailer",
];

#[cfg(test)]
#[path = "git_message_text_tests.rs"]
mod tests;
