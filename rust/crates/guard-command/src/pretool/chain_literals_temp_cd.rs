//! `cd "$(mktemp -d)" && node ../src/cli.js list` moves into a fresh scratch
//! directory. The workspace sandbox launches its shell with `TMPDIR` set to
//! the run's private writable directory, and `mktemp -d` with no template, or
//! with `-t TEMPLATE`, creates its directory there on GNU and BSD alike.
//!
//! When every substitution is such a directory and is the whole operand of a
//! `cd` or `pushd`, the sandbox launcher judges the command with the stand-in
//! in its place and runs the raw text, so the real `mktemp` runs inside the
//! sandbox. Outside the sandbox nothing changes: the stand-in still names
//! the absent root, never `$TMPDIR`.
//!
//! Such a directory may also be the whole value of a variable assignment
//! run as its own command, `export TODO_FILE=$(mktemp -d)/t.json`, optionally
//! followed by a literal relative path. The variable only carries the private
//! path into later programs, which the sandbox already bounds. Its name must
//! be ordinary, never one that steers loading, startup or lookup, and appear
//! nowhere else, so no later word expands, rebinds or unsets it. The body of
//! a quoted heredoc that a line of its own, `cat > PATH <<'EOF'`, only writes
//! to a file is data the shell never expands, so a mention there is not a use.

use super::super::{lex::identifier, listed, ordinary_name};
use super::{
    project as with_stand_ins, stand_in, substitution_spans, TEMPORARY_ROOT, TEMPORARY_VALUE,
};
use crate::shell_structure::{extract_heredocs, mask_heredoc_bodies, ShellHeredoc, ShellScanState};

/// List operators around a `cd` or assignment that runs as a command of its
/// own. A line break outside quotes and heredoc bodies ends a command as `;`
/// does; substitutions are never read inside a heredoc body.
const SEPARATORS: [&str; 4] = ["&&", "||", ";", "\n"];

/// Loader, search-path and temporary-directory names the shared chain-literal
/// screen does not already refuse, compared in upper case.
const LOADER_NAMES: &str = "BUNDLE_GEMFILE CLASSPATH CURL_HOME GCONV_PATH GEM_HOME GEM_PATH \
    GRADLE_OPTS JDK_JAVA_OPTIONS LOCPATH MAVEN_OPTS NLSPATH PKG_CONFIG_PATH TEMP TEMPDIR TMP \
    WGETRC _JAVA_OPTIONS";

/// The raw command with each substitution written as the temporary stand-in;
/// `None` unless every substitution is a private temporary directory that is
/// the whole operand of a `cd` or `pushd`, or the value of a private
/// assignment, run as its own command. The shared projection still refuses
/// `..` and any mention of `TMPDIR`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn project(command: &str) -> Option<String> {
    let projected = with_stand_ins(command, private_temporary_directory)?;
    let chars: Vec<char> = command.chars().collect();
    let (substitutions, _) = substitution_spans(command)?;
    let accepted = substitutions.iter().all(|substitution| {
        let (start, end) = (substitution.start, substitution.end);
        entered(&chars, start, end)
            || assigned(&chars, start, end).is_some_and(|name| named_once(&projected, &name))
    });
    accepted.then_some(projected)
}

/// Whether a `cd` operand is the stand-in for a fresh private temporary
/// directory. Its root must be absent, so a literal spelling of the stand-in
/// can only fail to change directory.
pub(crate) fn private_directory(target: &str) -> bool {
    target == TEMPORARY_VALUE && std::fs::symlink_metadata(TEMPORARY_ROOT).is_err()
}

/// How many times `text` names the stand-in's root.
pub(crate) fn mentions(text: &str) -> usize {
    text.matches(TEMPORARY_ROOT).count()
}

/// Whether the list item `item` only assigns the stand-in, or a literal path
/// below it, to an ordinary variable that `text`, the whole command, names
/// nowhere else: `NAME=VALUE` or `export NAME=VALUE`, quoted as `assignment`
/// reads it. Its root must be absent, as for a `cd` operand.
pub(crate) fn private_assignment(item: &str, text: &str) -> bool {
    let Some((before, after)) = item.split_once(TEMPORARY_VALUE) else {
        return false;
    };
    std::fs::symlink_metadata(TEMPORARY_ROOT).is_err()
        && assignment(before, after).is_some_and(|(name, head, rest)| {
            head.is_empty() && rest.is_empty() && named_once(text, name)
        })
}

/// `mktemp -d`, optionally with `-q` and one `-t TEMPLATE`. The template is
/// taken only right after the group that ends in `t`, where BSD reads it as
/// that option's prefix under `TMPDIR` and GNU as a name under `TMPDIR`;
/// without `-t` a template names a path below the working directory.
fn private_temporary_directory(body: &str) -> bool {
    if stand_in(body) != Some(TEMPORARY_VALUE) {
        return false;
    }
    let (mut directory, mut template_next) = (false, false);
    for word in body.split(' ').filter(|word| !word.is_empty()).skip(1) {
        match word.strip_prefix('-') {
            Some(flags) if !template_next && flags.matches('t').count() <= 1 => {
                if flags.contains('t') && !flags.ends_with('t') {
                    return false;
                }
                directory |= flags.contains('d');
                template_next = flags.ends_with('t');
            }
            None if template_next => template_next = false,
            _ => return false,
        }
    }
    directory && !template_next
}

/// Whether the substitution at character span `start..end`, bare or exactly
/// double-quoted, is the only operand of a `cd` or `pushd` that starts a list
/// item and ends it.
fn entered(chars: &[char], start: usize, end: usize) -> bool {
    let quoted = start > 0 && chars.get(start - 1) == Some(&'"') && chars.get(end) == Some(&'"');
    let (start, end) = if quoted {
        (start - 1, end + 1)
    } else {
        (start, end)
    };
    let (Some(before), Some(after)) = (chars.get(..start), chars.get(end..)) else {
        return false;
    };
    let (before, after): (String, String) = (before.iter().collect(), after.iter().collect());
    let Some(head) = before.strip_suffix([' ', '\t']) else {
        return false;
    };
    let head = head.trim_end_matches([' ', '\t']);
    let Some(head) = head
        .strip_suffix("pushd")
        .or_else(|| head.strip_suffix("cd"))
    else {
        return false;
    };
    starts_item(head.trim_end_matches([' ', '\t']))
        && ends_item(after.trim_start_matches([' ', '\t']))
}

/// The variable the substitution at character span `start..end` assigns when
/// it is the value, as `assignment` reads it, of an assignment that starts a
/// list item and ends it.
fn assigned(chars: &[char], start: usize, end: usize) -> Option<String> {
    let before: String = chars.get(..start)?.iter().collect();
    let after: String = chars.get(end..)?.iter().collect();
    let (name, head, rest) = assignment(&before, &after)?;
    if starts_item(head) && ends_item(rest) {
        Some(name.to_owned())
    } else {
        None
    }
}

/// Reads `before VALUE after` as `NAME=VALUE` or `export NAME=VALUE`, with a
/// literal relative suffix after the value; the value is bare, double-quoted
/// on its own (`"VALUE"/t.json`) or double-quoted with its suffix. Returns the
/// assignable name, the text before the assignment and its `export`, and the
/// text after it, each trimmed of the blanks next to the assignment.
fn assignment<'a>(before: &'a str, after: &'a str) -> Option<(&'a str, &'a str, &'a str)> {
    let (head, rest) = match before.strip_suffix('"') {
        Some(head) => match after.strip_prefix('"') {
            Some(rest) => (head, &rest[suffix_length(rest)..]),
            None => (head, after[suffix_length(after)..].strip_prefix('"')?),
        },
        None => (before, &after[suffix_length(after)..]),
    };
    let head = head.strip_suffix('=')?;
    let item = head.trim_end_matches(|c: char| c == '_' || c.is_ascii_alphanumeric());
    let name = &head[item.len()..];
    let item = match item.strip_suffix([' ', '\t']) {
        Some(spaced) => {
            let spaced = spaced.trim_end_matches([' ', '\t']);
            spaced.strip_suffix("export").unwrap_or(spaced)
        }
        None => item,
    };
    assignable(name).then_some((
        name,
        item.trim_end_matches([' ', '\t']),
        rest.trim_start_matches([' ', '\t']),
    ))
}

/// The length of the literal relative path that may follow the value:
/// `/`-separated components of letters, digits, `.`, `_` and `-`, none of
/// them holding `..`. No expansion, glob or quote can extend it.
fn suffix_length(text: &str) -> usize {
    let mut length = 0;
    while let Some(rest) = text[length..].strip_prefix('/') {
        let component = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')))
            .unwrap_or(rest.len());
        if component == 0 || rest[..component].contains("..") {
            break;
        }
        length += 1 + component;
    }
    length
}

/// A name the shared chain-literal screen treats as ordinary that is no
/// loader, search-path or temporary-directory name either.
fn assignable(name: &str) -> bool {
    identifier(name) && ordinary_name(name) && !listed(LOADER_NAMES, &name.to_ascii_uppercase())
}

/// Whether `text` names `name` exactly once as a whole word, so nothing else
/// in the command expands, sets, exports or unsets the variable. Bodies that
/// `cat` only writes to a file are not read.
fn named_once(text: &str, name: &str) -> bool {
    written_data_masked(text)
        .split(|c: char| c != '_' && !c.is_ascii_alphanumeric())
        .filter(|word| *word == name)
        .count()
        == 1
}

/// `text` with the body of each heredoc that `written_data` accepts blanked.
/// Unchanged when a `<<` is not a heredoc the shared parser reads, or when the
/// command could define `cat` as something other than the program.
fn written_data_masked(text: &str) -> String {
    let heredocs = extract_heredocs(text);
    let masked = mask_heredoc_bodies(text, &heredocs);
    let operators = crate::shell_structure::heredoc_operators(&masked);
    if operators != heredocs.len() || redefines_cat(&masked) {
        return text.to_owned();
    }
    let chars: Vec<char> = masked.chars().collect();
    let written: Vec<ShellHeredoc> = heredocs
        .into_iter()
        .filter(|heredoc| written_data(&chars, heredoc))
        .collect();
    mask_heredoc_bodies(text, &written)
}

/// Whether `heredoc` has a quoted delimiter, closes, and is the first heredoc
/// on a top-level line that is exactly `cat > PATH`, `cat >> PATH` or the
/// same with the path joined to the operator, so its body is data written to
/// a plain relative or absolute path. `chars` is the command with every
/// heredoc body blanked.
fn written_data(chars: &[char], heredoc: &ShellHeredoc) -> bool {
    if !heredoc.quoted || heredoc.body_end >= chars.len() {
        return false;
    }
    let line_start = chars[..heredoc.operator_start]
        .iter()
        .rposition(|&c| c == '\n')
        .map_or(0, |at| at + 1);
    let line_end = chars[heredoc.declaration_end..]
        .iter()
        .position(|&c| c == '\n')
        .map_or(chars.len(), |at| heredoc.declaration_end + at);
    if line_end + 1 != heredoc.body_start || (line_start >= 2 && chars[line_start - 2] == '\\') {
        return false;
    }
    let mut state = ShellScanState::new();
    let mut index = 0;
    while index < line_start {
        index = state.advance(chars, index);
    }
    if index != line_start || !state.is_top_level() {
        return false;
    }
    let declaration: String = chars[line_start..heredoc.operator_start]
        .iter()
        .chain(&chars[heredoc.declaration_end..line_end])
        .collect();
    let words: Vec<&str> = declaration.split_whitespace().collect();
    match words.as_slice() {
        ["cat", ">" | ">>", path] => plain_path(path),
        ["cat", redirect] => redirect
            .strip_prefix(">>")
            .or_else(|| redirect.strip_prefix('>'))
            .is_some_and(plain_path),
        _ => false,
    }
}

/// A path spelled with letters, digits, `.`, `_`, `-` and `/` only, so the
/// shell neither expands nor splits it, that is no option.
fn plain_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('-')
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

/// Whether `text` might make `cat` an alias or a function. A `.` stays inside
/// a word, so a path such as `alias.txt` is a file name rather than `alias`.
fn redefines_cat(text: &str) -> bool {
    let words: Vec<&str> = text
        .split(|c: char| c != '_' && c != '.' && !c.is_ascii_alphanumeric())
        .collect();
    words.contains(&"alias")
        || words.contains(&"function")
        || text.match_indices("cat").any(|(at, _)| {
            text[at + 3..]
                .trim_start_matches([' ', '\t'])
                .starts_with('(')
        })
}

/// Whether `head`, the text before a command, is empty or ends a list item.
/// A line break after a backslash only continues the command.
fn starts_item(head: &str) -> bool {
    head.is_empty()
        || (SEPARATORS
            .iter()
            .any(|&separator| head.ends_with(separator))
            && !head.ends_with("\\\n"))
}

/// Whether `rest`, the text after a command, is empty or ends its list item.
fn ends_item(rest: &str) -> bool {
    rest.is_empty()
        || SEPARATORS
            .iter()
            .any(|&separator| rest.starts_with(separator))
}

#[cfg(test)]
#[path = "chain_literals_temp_cd_tests.rs"]
mod tests;
