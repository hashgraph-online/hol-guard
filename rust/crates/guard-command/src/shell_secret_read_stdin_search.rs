//! A search tool given a home dotfile's path as its only word.
//!
//! `grep ~/.secrets/key.txt` names no file to search: the path is grep's
//! pattern and grep reads standard input. The operand reader is right to skip
//! it, so the read-only lookup lane saw no target and passed the search, while
//! `sed`, `awk`, `tr`, `ag` and every other reader with the same shape went to
//! review. An agent never needs a search whose only word is the path of a file
//! in the user's private home directories; that word is the read it meant to
//! make, so the lane stops vouching for it and the ordinary review applies.
//!
//! The rule stays narrow so ordinary searches never reach it:
//! - grep must not be recursive, so `grep -r ~/.aws/credentials .` still
//!   searches the tree for references to that path;
//! - there must be no file operand and no `-e`/`-f` pattern option;
//! - the pattern must be written as a path under the home directory whose
//!   first component is hidden (`~/.ssh/…`, `$HOME/.config/…`), so word
//!   patterns and paths inside a project are never treated as reads.
//!
//! Only a search with no other input counts, so a fed search such as
//! `ps aux | grep ~/.ssh/id_rsa` or `grep ~/.ssh/id_rsa < notes.txt` is
//! never asked. [`lone_home_dotpath_search`] applies the rule to a
//! whole command: no exact-safe proof vouches for it, and an enabled
//! extension permission cannot settle the review it keeps.

use std::path::Path;

const GREP_FAMILY: &[&str] = &["grep", "egrep", "fgrep"];
const PATTERN_OPTIONS: &[&str] = &["-e", "--regexp", "-f", "--file"];
const GREP_VALUE_OPTIONS: &[&str] = &[
    "--after-context",
    "--before-context",
    "--context",
    "--devices",
    "--exclude",
    "--exclude-dir",
    "--include",
    "--max-count",
];
const RG_VALUE_OPTIONS: &[&str] = &[
    "-A",
    "-B",
    "-C",
    "-d",
    "-E",
    "-g",
    "-j",
    "-m",
    "-M",
    "-r",
    "-t",
    "-T",
    "--after-context",
    "--before-context",
    "--color",
    "--colors",
    "--context",
    "--context-separator",
    "--dfa-size-limit",
    "--encoding",
    "--engine",
    "--field-context-separator",
    "--field-match-separator",
    "--glob",
    "--hostname-bin",
    "--hyperlink-format",
    "--iglob",
    "--ignore-file",
    "--max-columns",
    "--max-count",
    "--max-depth",
    "--maxdepth",
    "--max-filesize",
    "--path-separator",
    "--pre",
    "--pre-glob",
    "--regex-size-limit",
    "--replace",
    "--sort",
    "--sortr",
    "--threads",
    "--type",
    "--type-add",
    "--type-clear",
    "--type-not",
];

/// Whether a command's first pipeline stage runs `grep`/`rg` with a home
/// dotfile's path as its only word and nothing feeding it.
///
/// `grep ~/.secrets/key.txt` names no file: the path is the pattern and the
/// search reads stdin, so no search proof ever sees the read it meant. The
/// shape is no search an agent needs, so nothing vouches for it and no Allow
/// settles it. A search fed by a pipe or an input redirect has real input,
/// and a quoted `~` or `$HOME` is literal text to look for, so neither counts.
pub(crate) fn lone_home_dotpath_search(
    model: &crate::CanonicalCommandV1,
    home_dir: Option<&str>,
) -> bool {
    let home = home_dir.map(Path::new);
    model.segments.iter().any(|segment| {
        segment.pipeline_index == 0
            && !has_input_redirect_syntax(&segment.text)
            && segment.executable.as_deref().is_some_and(|executable| {
                let name = executable.rsplit(['/', '\\']).next().unwrap_or(executable);
                let Some(pattern) = lone_pattern(name, &segment.arguments) else {
                    return false;
                };
                !pattern_is_quoted(&segment.text, pattern)
                    && lone_search_pattern_names_home_dotpath(name, &segment.arguments, home)
            })
    })
}

/// Whether quoting keeps the shell from expanding the pattern's home word,
/// so the search looks for the literal text `~/...` or `$HOME/...`. An
/// absolute path means the same quoted or not, double quotes still expand
/// `$HOME`, and quotes in other words do not change the pattern.
fn pattern_is_quoted(text: &str, pattern: &str) -> bool {
    let tilde = pattern.starts_with('~');
    if !tilde && !pattern.starts_with('$') {
        return false;
    }
    // A quote immediately before a match is not proof of quoting:
    // grep ''$HOME/.ssh/id_rsa expands HOME after the empty quotes.
    // Scan actual shell quote/escape state, ignoring comment text.
    let visible = crate::shell_structure::mask_shell_comments(text);
    let chars: Vec<char> = visible.chars().collect();
    let target: Vec<char> = pattern.chars().collect();
    let mut state = crate::shell_structure::ShellScanState::new();
    let mut index = 0;
    let mut literal_match = false;
    while index < chars.len() {
        let quote = state.snapshot().0;
        // A backslash escapes the next home marker outside single quotes,
        // including inside double quotes. The scan consumes both characters.
        if chars[index] == '\\'
            && quote != Some('\'')
            && chars
                .get(index + 1..)
                .is_some_and(|rest| rest.starts_with(&target))
        {
            literal_match = true;
        }
        if chars[index..].starts_with(&target) {
            // Tilde remains literal in either quote style. HOME expands
            // inside double quotes, but not inside single quotes.
            let literal = quote == Some('\'') || (tilde && quote == Some('"'));
            if !literal {
                return false;
            }
            literal_match = true;
        }
        index = state.advance(&chars, index).max(index + 1);
    }
    // Do not return for a literal contiguous match yet: it might belong
    // to a separate option value while the pattern itself expands HOME.
    // A single-quoted home marker can join an unquoted suffix into one
    // literal shell word: grep '$HOME'/.config/example. Do not match that
    // spelling as a substring of an assignment or option value: an unrelated
    // quoted decoy must never shield the actual expanding search argument.
    let Some((marker, suffix)) = ["$HOME", "${HOME}", "~"]
        .into_iter()
        .find_map(|marker| pattern.strip_prefix(marker).map(|suffix| (marker, suffix)))
    else {
        return false;
    };
    let joined = format!("'{marker}'{suffix}");
    let mut words = Vec::new();
    let mut start = None;
    let mut scan = crate::shell_structure::ShellScanState::new();
    let mut cursor = 0;
    while cursor < chars.len() {
        if scan.is_top_level() && chars[cursor].is_whitespace() {
            if let Some(begin) = start.take() {
                words.push(chars[begin..cursor].iter().collect::<String>());
            }
        } else if start.is_none() {
            start = Some(cursor);
        }
        cursor = scan.advance(&chars, cursor).max(cursor + 1);
    }
    if let Some(begin) = start {
        words.push(chars[begin..].iter().collect::<String>());
    }
    // A second home-bearing word could be the real expanding pattern while
    // the joined literal was consumed as an option value or assignment.
    // Resolve that ambiguity fail-closed instead of granting an exact allow.
    let home_words: Vec<&String> = words
        .iter()
        .filter(|word| word.contains("$HOME") || word.contains("${HOME}") || word.contains('~'))
        .collect();
    home_words.len() == 1 && (literal_match || home_words[0] == &joined)
}

/// A quoted or escaped '<' is argument text, not input redirection.
/// Respect shell structure and mask comments before reading the operators.
pub(crate) fn has_input_redirect_syntax(command: &str) -> bool {
    let visible = crate::shell_structure::mask_shell_comments(command);
    let chars: Vec<char> = visible.chars().collect();
    let mut state = crate::shell_structure::ShellScanState::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '<' && state.is_top_level() {
            return true;
        }
        index = state.advance(&chars, index).max(index + 1);
    }
    false
}

/// Whether this `grep`/`rg` call's only word is a path into a hidden entry
/// of the home directory.
pub(crate) fn lone_search_pattern_names_home_dotpath(
    command: &str,
    args: &[String],
    home_dir: Option<&Path>,
) -> bool {
    let Some(pattern) = lone_pattern(command, args) else {
        return false;
    };
    let relative = if let Some(rest) = pattern.strip_prefix("~/") {
        rest.to_owned()
    } else if let Some(rest) = pattern.strip_prefix("$HOME/") {
        rest.to_owned()
    } else if let Some(rest) = pattern.strip_prefix("${HOME}/") {
        rest.to_owned()
    } else {
        let Some(home) = home_dir else {
            return false;
        };
        match under_home(Path::new(pattern), home) {
            Some(rest) => rest,
            None => return false,
        }
    };
    let first = relative.split('/').next().unwrap_or("");
    first.len() > 1 && first.starts_with('.') && first != ".."
}

enum GrepShort<'a> {
    Recursive,
    ExplicitPattern,
    Directory(Option<&'a str>),
    Value(bool),
}

// GNU grep combines short options. A value-taking option consumes the rest
// of that group or the following word; -T is NOT value-taking in grep.
fn grep_short(arg: &str) -> Option<GrepShort<'_>> {
    let flags = arg.strip_prefix('-')?;
    if flags.is_empty() || flags.starts_with('-') {
        return None;
    }
    for (index, flag) in flags.char_indices() {
        let remaining = &flags[index + flag.len_utf8()..];
        match flag {
            'r' | 'R' => return Some(GrepShort::Recursive),
            'e' | 'f' => return Some(GrepShort::ExplicitPattern),
            'd' => {
                return Some(GrepShort::Directory(
                    (!remaining.is_empty()).then_some(remaining),
                ))
            }
            'A' | 'B' | 'C' | 'D' | 'm' => {
                return Some(GrepShort::Value(remaining.is_empty()));
            }
            _ => {}
        }
    }
    None
}

// Ripgrep clusters boolean short flags with -e/-f and arity-bearing flags.
// The latter own the rest of the cluster, so a later letter is a value,
// not another option. Do not treat an explicit pattern as a lone stdin search.
fn rg_short(arg: &str) -> Option<GrepShort<'_>> {
    let flags = arg.strip_prefix('-')?;
    if flags.is_empty() || flags.starts_with('-') {
        return None;
    }
    for (index, flag) in flags.char_indices() {
        let remaining = &flags[index + flag.len_utf8()..];
        match flag {
            'e' | 'f' => return Some(GrepShort::ExplicitPattern),
            'A' | 'B' | 'C' | 'd' | 'E' | 'g' | 'j' | 'm' | 'M' | 'r' | 't' | 'T' => {
                return Some(GrepShort::Value(remaining.is_empty()));
            }
            _ => {}
        }
    }
    None
}

fn lone_pattern<'a>(command: &str, args: &'a [String]) -> Option<&'a str> {
    let grep_like = GREP_FAMILY.contains(&command);
    if !grep_like && command != "rg" {
        return None;
    }
    let mut pattern: Option<&str> = None;
    let mut skip_value = false;
    let mut directory_value_pending = false;
    let mut after_options = false;
    for arg in args {
        if directory_value_pending {
            directory_value_pending = false;
            if arg == "recurse" {
                return None;
            }
            continue;
        }
        if skip_value {
            skip_value = false;
            continue;
        }
        if after_options || !arg.starts_with('-') || arg == "-" {
            if arg == "-" || pattern.is_some() {
                // A second word is a file operand (or stdin named outright).
                return None;
            }
            pattern = Some(arg);
            continue;
        }
        if arg == "--" {
            after_options = true;
            continue;
        }
        let flag = arg.split_once('=').map_or(arg.as_str(), |(f, _)| f);
        if PATTERN_OPTIONS.contains(&flag)
            || (!arg.starts_with("--") && (arg.starts_with("-e") || arg.starts_with("-f")))
        {
            return None;
        }
        if command == "rg" && matches!(flag, "--files" | "--type-list") {
            return None;
        }
        if grep_like {
            if matches!(flag, "--recursive" | "--dereference-recursive") {
                return None;
            }
            if flag == "--directories" {
                if let Some(value) = arg.strip_prefix("--directories=") {
                    if value == "recurse" {
                        return None;
                    }
                } else {
                    directory_value_pending = true;
                }
                continue;
            }
            if let Some(option) = grep_short(arg) {
                match option {
                    GrepShort::Recursive | GrepShort::ExplicitPattern => return None,
                    GrepShort::Directory(Some("recurse")) => return None,
                    GrepShort::Directory(Some(_)) => {}
                    GrepShort::Directory(None) => directory_value_pending = true,
                    GrepShort::Value(needs_next) => skip_value = needs_next,
                }
                continue;
            }
        }
        if command == "rg" {
            if let Some(option) = rg_short(arg) {
                match option {
                    GrepShort::ExplicitPattern => return None,
                    GrepShort::Value(needs_next) => skip_value = needs_next,
                    _ => {}
                }
                continue;
            }
        }
        let value_options = if grep_like {
            GREP_VALUE_OPTIONS
        } else {
            RG_VALUE_OPTIONS
        };
        if value_options.contains(&arg.as_str()) {
            skip_value = true;
        }
    }
    pattern
}

/// The pattern's path below the home directory, matching either spelling of
/// each side: macOS reports `/tmp/...` and `/private/tmp/...` for one place.
fn under_home(pattern: &Path, home: &Path) -> Option<String> {
    let homes = [Some(home.to_path_buf()), std::fs::canonicalize(home).ok()];
    let patterns = [Some(pattern.to_path_buf()), canonical_prefix(pattern)];
    for home in homes.iter().flatten() {
        for pattern in patterns.iter().flatten() {
            if let Ok(rest) = pattern.strip_prefix(home) {
                return Some(rest.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// The path with its deepest existing ancestor resolved, so a missing file
/// under a symlinked directory still resolves.
fn canonical_prefix(path: &Path) -> Option<std::path::PathBuf> {
    let mut tail = Vec::new();
    let mut current = path;
    loop {
        if let Ok(resolved) = std::fs::canonicalize(current) {
            return Some(tail.iter().rev().fold(resolved, |acc, part| acc.join(part)));
        }
        tail.push(current.file_name()?.to_owned());
        current = current.parent()?;
    }
}
