//! `fd` prints matching names and never file contents. By default it skips
//! hidden entries and ignored paths and does not follow links, so a names-only
//! listing is proven when no option widens that scope or runs a command per
//! match, and every search root clears the same screens as an `rg` root.
use super::options::unsafe_search_value;
use super::{tree, ReadContext, SearchValueRole};

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
    value.contains(['*', '?', '[', ']', '{', '}', '$', '`'])
        || (unsafe_search_value(SearchValueRole::Path, value, context)
            && !tree::rg_root_inside_cwd(value, context)
            && !tree::listing_root_below_home(value, context)
            && !tree::safe_recursive_search_target(value, context))
}

fn unsafe_value(role: SearchValueRole, value: &str, context: ReadContext<'_>) -> bool {
    match role {
        SearchValueRole::Path => unsafe_root(value, context),
        _ => unsafe_search_value(role, value, context),
    }
}

pub(super) fn safe_fd_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    let mut pending: Option<SearchValueRole> = None;
    let mut options_enabled = true;
    let mut pattern_seen = false;
    let mut root_seen = false;
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
                continue;
            }
            let Some(role) = value_role(name) else {
                return false;
            };
            if matches!(role, SearchValueRole::Path) {
                root_seen = true;
            }
            // The shell does not expand `~` after `--search-path=`.
            if attached.is_empty() {
                pending = Some(role);
            } else if (matches!(role, SearchValueRole::Path) && attached.starts_with('~'))
                || unsafe_value(role, attached, context)
            {
                return false;
            }
            continue;
        }
        if options_enabled && argument.starts_with('-') && argument.len() > 1 {
            for (offset, option) in argument[1..].char_indices() {
                if SHORT_FLAGS.contains(&option) {
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
        if pattern_seen {
            if unsafe_root(argument, context) {
                return false;
            }
            root_seen = true;
        } else {
            pattern_seen = true;
        }
    }
    // Without a root fd lists the cwd, the same listing as an explicit `.`
    // root, so both spellings get the same decision.
    pending.is_none() && (root_seen || !unsafe_root(".", context))
}
