//! `fd` prints matching names and never file contents. By default it skips
//! hidden entries and ignored paths and does not follow links, so a names-only
//! listing is proven when no option widens that scope or runs a command per
//! match, and every search root clears the same screens as an `rg` root.
use super::options::unsafe_search_value;
use super::{sibling, tree, ReadContext, SearchValueRole};

/// Options that take no value and only change matching or output format.
const FLAGS: &[&str] = &[
    "--case-sensitive",
    "--ignore-case",
    "--fixed-strings",
    "--glob",
    "--regex",
    "--absolute-path",
    "--full-path",
    "--print0",
    "--quiet",
    "--show-errors",
    "--prune",
    "--one-file-system",
    "--strip-cwd-prefix",
];

const SHORT_FLAGS: &[char] = &['s', 'i', 'F', 'g', 'a', 'p', '0', '1', 'q'];

fn value_role(name: &str) -> Option<SearchValueRole> {
    match name {
        "--exclude" => Some(SearchValueRole::Glob),
        "--search-path" => Some(SearchValueRole::Path),
        "--type" | "--extension" | "--max-depth" | "--min-depth" | "--exact-depth" | "--size"
        | "--changed-within" | "--changed-before" | "--max-results" | "--color" | "--threads" => {
            Some(SearchValueRole::Other)
        }
        _ => None,
    }
}

fn short_value_role(option: char) -> Option<SearchValueRole> {
    match option {
        'E' => Some(SearchValueRole::Glob),
        't' | 'e' | 'd' | 'S' | 'c' | 'j' => Some(SearchValueRole::Other),
        _ => None,
    }
}

fn unsafe_root(value: &str, context: ReadContext<'_>) -> bool {
    // fd does not expand globs or variables in a root; the shell might, and
    // the proof would then describe a different directory, so refuse them.
    if value.contains(['*', '?', '{', '}', '$', '`']) {
        return true;
    }
    // A framework route is spelled with brackets. `fd -e tsx . app/[locale]`
    // searches one directory of a Next.js application, and a class that
    // matches nothing is handed to fd as the word that was typed, so the
    // directory it names is screened as the same path without brackets would
    // be. A class the shell could expand names a different directory than the
    // proof describes, so it keeps its review.
    if value.contains(['[', ']']) {
        return !tree::safe_literal_bracket_search_target(value, context);
    }
    unsafe_search_value(SearchValueRole::Path, value, context)
        && !tree::rg_root_inside_cwd(value, context)
        && !tree::listing_root_below_home(value, context)
        && !tree::safe_recursive_search_target(value, context)
        // An agent in one repository names a neighbour to find a file by
        // name. `fd` skips the same hidden and ignored entries `rg` skips,
        // and prints names rather than contents, so the walk that proves an
        // `rg` root proves this listing too, once it reads the ignore files
        // `fd` reads rather than the ones `rg` reads.
        && !sibling::fd_sibling_repository_root(value, context)
}

fn unsafe_value(role: SearchValueRole, value: &str, context: ReadContext<'_>) -> bool {
    match role {
        SearchValueRole::Path => unsafe_root(value, context),
        _ => unsafe_search_value(role, value, context),
    }
}

/// Whether a names-only `fd` search may start at a home dot-directory.
///
/// `fd` refuses every option that would widen such a listing: `--hidden`,
/// `--follow` and `--exec` are not among the options this screen accepts, so
/// the search never prints a hidden entry, never leaves the tree through a
/// link and never runs a program per match. What is left is a name walk whose
/// output the pattern bounds, the same bound `find` carries where a depth
/// bound would otherwise be required, under the same three conditions: the
/// root is one tool's own directory rather than a root several tools keep
/// their directories under, the pattern names something specific enough to be
/// a name the agent already had, and it cannot select the file a tool keeps
/// its own login in.
///
/// The root condition is what carries the rest. Below one tool's directory a
/// name walk prints what a listing of that directory prints, which is the
/// plan, session and script names Guard admits today; below `~/.config` it
/// would print the entry names inside `~/.config/gh`, which is a store, and no
/// pattern makes that safe.
///
/// `--full-path` and `--absolute-path` match the whole path rather than the
/// entry name, so a directory prefix satisfies the pattern and it bounds
/// nothing.
fn hidden_home_listing(
    pattern: Option<&str>,
    path_matching: bool,
    value: &str,
    context: ReadContext<'_>,
) -> bool {
    pattern.is_some_and(|pattern| {
        !path_matching
            && literal_word(pattern)
            && !bare_format_suffix(pattern)
            && !crate::credential_store_names::pattern_can_select_secret(pattern)
            && super::super::read_paths::home_hidden_tool_directory(
                value,
                context.home_dir,
                context.cwd,
            )
    })
}

/// Formats a tool writes its own files in. `fd` matches anywhere in a name, so
/// a suffix on its own selects every file of that format the tree holds,
/// including the one the tool keeps its login in: `fd json ~/.codex` prints
/// `auth.json`. A suffix is not a name an agent already had, so it bounds
/// nothing and the walk keeps its review.
const FORMAT_SUFFIXES: &[&str] = &[
    "cfg",
    "conf",
    "config",
    "ini",
    "json",
    "jsonc",
    "plist",
    "properties",
    "toml",
    "xml",
    "yaml",
    "yml",
];

/// `fd` matches its pattern anywhere in a name and reads `.` as a wildcard,
/// so a fragment of a suffix selects the same files the whole suffix does:
/// `fd son ~/.codex` and `fd h.json ~/.codex` both print `auth.json`. A
/// pattern is read the way a secret stem is, overlapping a suffix in either
/// direction rather than spelling one exactly.
fn bare_format_suffix(pattern: &str) -> bool {
    let lowered = pattern.to_ascii_lowercase();
    let lowered = lowered.trim_start_matches('.');
    FORMAT_SUFFIXES
        .iter()
        .any(|suffix| crate::credential_store_names::wildcards_reach(lowered, suffix))
}

/// A pattern of word characters alone. `fd` reads its pattern as a regular
/// expression, and one carrying no metacharacter beyond `.` selects the names
/// that hold that word rather than whatever the tree happens to contain. A
/// `.` is a wildcard there, which the screen above reads as one.
fn literal_word(pattern: &str) -> bool {
    (3..=128).contains(&pattern.len())
        && !pattern.starts_with('.')
        && pattern.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
}

pub(super) fn safe_fd_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    let mut pending: Option<SearchValueRole> = None;
    let mut options_enabled = true;
    let mut pattern: Option<&str> = None;
    let mut root_seen = false;
    let mut path_matching = false;
    // A root the ordinary screens refuse may still be a home dot-directory the
    // pattern bounds, which only the whole argument list can answer.
    let mut deferred: Vec<&str> = Vec::new();
    for argument in arguments {
        if let Some(role) = pending.take() {
            if unsafe_value(role, argument, context) {
                return false;
            }
            continue;
        }
        if options_enabled && argument == "--" {
            options_enabled = false;
            continue;
        }
        if options_enabled && argument.starts_with("--") {
            let (name, attached) = argument.split_once('=').unwrap_or((argument.as_str(), ""));
            if FLAGS.contains(&name) && attached.is_empty() {
                path_matching |= matches!(name, "--full-path" | "--absolute-path");
                continue;
            }
            let Some(role) = value_role(name) else {
                return false;
            };
            if matches!(role, SearchValueRole::Path) {
                root_seen = true;
            }
            // The shell does not expand `~` after `--search-path=`, and it
            // globs the whole word rather than the part after `=`: a
            // repository holding `--search-path=app/s` turns
            // `--search-path=app/[slug]` into a root the bracket proof never
            // walked. Only the separate word is the word that was proven.
            if attached.is_empty() {
                pending = Some(role);
            } else if (matches!(role, SearchValueRole::Path)
                && (attached.starts_with('~') || attached.contains(['[', ']'])))
                || unsafe_value(role, attached, context)
            {
                return false;
            }
            continue;
        }
        if options_enabled && argument.starts_with('-') && argument.len() > 1 {
            for (offset, option) in argument[1..].char_indices() {
                if SHORT_FLAGS.contains(&option) {
                    path_matching |= matches!(option, 'p' | 'a');
                    continue;
                }
                let Some(role) = short_value_role(option) else {
                    return false;
                };
                let attached = &argument[1 + offset + option.len_utf8()..];
                if attached.is_empty() {
                    pending = Some(role);
                } else if unsafe_value(role, attached, context) {
                    return false;
                }
                break;
            }
            continue;
        }
        if pattern.is_some() {
            if unsafe_root(argument, context) {
                deferred.push(argument.as_str());
            }
            root_seen = true;
        } else {
            pattern = Some(argument.as_str());
        }
    }
    // Without a root fd lists the cwd, the same listing as an explicit `.`
    // root, so both spellings get the same decision.
    pending.is_none()
        && (root_seen || !unsafe_root(".", context))
        && deferred
            .iter()
            .all(|root| hidden_home_listing(pattern, path_matching, root, context))
}
