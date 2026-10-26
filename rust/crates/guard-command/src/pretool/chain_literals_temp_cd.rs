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
//!
//! A bare assignment that starts the command may also be expanded later,
//! `tmp=$(mktemp -d) && python3 todo.py --file "$tmp/tasks.json" list`, when
//! every later list item follows `&&`. The assignment fails when `mktemp`
//! does, so each `$tmp` after it holds the fresh directory, and the sandbox
//! shape reads those expansions as `$TMPDIR`, the private directory under it.

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

/// The temporary-directory names in `LOADER_NAMES`.
const TEMPORARY_NAMES: [&str; 3] = ["TEMP", "TEMPDIR", "TMP"];

/// The raw command with each substitution written as the temporary stand-in;
/// `None` unless every substitution is a private temporary directory that is
/// the whole operand of a `cd` or `pushd`, or the value of a private
/// assignment, run as its own command. The shared projection still refuses
/// `..` and any mention of `TMPDIR`.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn project(command: &str) -> Option<String> {
    let mut projected = with_stand_ins(command, private_temporary_directory)?;
    let chars: Vec<char> = command.chars().collect();
    let (substitutions, _) = substitution_spans(command)?;
    for substitution in &substitutions {
        let (start, end) = (substitution.start, substitution.end);
        if entered(&chars, start, end) {
            continue;
        }
        let name = assigned(&chars, start, end)?;
        if !named_once(&projected, &name) {
            projected = expanded_privately(&projected, &name)?;
        }
    }
    Some(projected)
}

/// The projection when it reads a later expansion of the fresh directory as
/// `$TMPDIR`; the raw command never names `TMPDIR`, or `project` refuses it.
pub(crate) fn expanded(command: &str) -> Option<String> {
    project(command).filter(|projected| projected.contains("TMPDIR"))
}

/// Words that run code later, bind a variable by an operand name or change
/// directory, which would let a later expansion name something other than
/// the fresh directory.
#[cfg_attr(not(unix), allow(dead_code))]
const UNTRACKED_WORDS: [&str; 22] = [
    ".",
    "source",
    "eval",
    "trap",
    "alias",
    "cd",
    "pushd",
    "popd",
    "read",
    "printf",
    "declare",
    "typeset",
    "local",
    "export",
    "readonly",
    "unset",
    "mapfile",
    "readarray",
    "getopts",
    "let",
    "wait",
    "coproc",
];

/// `projected` with each later `$NAME` or `${NAME}` written as `$TMPDIR` or
/// `${TMPDIR}`, when `NAME=VALUE` is a bare assignment that starts the
/// command, every later list item follows `&&`, and the only expansions are
/// those of the name outside single quotes. The assignment's status is the
/// substitution's, so each expansion runs in the same shell once `mktemp`
/// made the directory. Any `;`, `|`, `&`, line break, backtick, backslash,
/// subshell, untracked word, other expansion, or mention of the name that
/// quote removal would form, returns `None`. `$TMPDIR` holds the fresh
/// directory, so the sandbox shape judges the expansion no narrower than the
/// shell runs it.
#[cfg_attr(not(unix), allow(dead_code))]
fn expanded_privately(projected: &str, name: &str) -> Option<String> {
    let head = projected.trim_start_matches([' ', '\t']);
    let dequoted = projected.replace(['\'', '"', '\\'], "");
    if !head.strip_prefix(name)?.starts_with('=')
        || dequoted
            .split_whitespace()
            .any(|word| UNTRACKED_WORDS.contains(&word))
    {
        return None;
    }
    let chars: Vec<char> = projected.chars().collect();
    let ident = |c: &char| c.is_ascii_alphanumeric() || *c == '_';
    let word_end = |from: usize| {
        chars[from..]
            .iter()
            .position(|c| !ident(c))
            .map_or(chars.len(), |at| from + at)
    };
    let (mut single, mut double, mut expansions) = (false, false, 0usize);
    let mut out = String::with_capacity(projected.len() + 16);
    let mut index = 0usize;
    while let Some(&current) = chars.get(index) {
        let quoted = single || double;
        match current {
            '\n' | '`' => return None,
            '\\' if !single => return None,
            '\'' if !double => single = !single,
            '"' if !single => double = !double,
            ';' | '(' | ')' | '|' if !quoted => return None,
            '&' if !quoted => {
                if chars.get(index + 1) != Some(&'&') {
                    return None;
                }
                out.push(current);
                index += 1;
            }
            '$' if !single => {
                let braced = chars.get(index + 1) == Some(&'{');
                let from = index + 1 + usize::from(braced);
                let end = word_end(from);
                if chars[from..end].iter().collect::<String>() != name
                    || (braced && chars.get(end) != Some(&'}'))
                {
                    return None;
                }
                out.push_str(if braced { "${TMPDIR" } else { "$TMPDIR" });
                expansions += 1;
                index = end;
                continue;
            }
            _ => {}
        }
        out.push(current);
        index += 1;
    }
    // Quote removal forms each name the shell binds or expands, so the name
    // appears there only as the assignment and those expansions.
    let mentions = dequoted
        .split(|c: char| !(c == '_' || c.is_ascii_alphanumeric()))
        .filter(|word| *word == name)
        .count();
    (mentions == 1 + expansions && expansions > 0 && !single && !double).then_some(out)
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
/// loader, search-path or temporary-directory name either. Programs read
/// only the upper-case temporary-directory names from the environment, so a
/// shell variable such as `tmp` is ordinary.
fn assignable(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let temporary = TEMPORARY_NAMES.contains(&upper.as_str());
    identifier(name)
        && ordinary_name(name)
        && if temporary {
            name != upper
        } else {
            !listed(LOADER_NAMES, &upper)
        }
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
