//! The `git stash` spellings that only print: `stash list` and `stash show`.
//!
//! Every other stash spelling moves work. `push`, `save`, `pop`, `apply`,
//! `drop`, `clear`, `branch` and `store` write a ref, the index or the
//! worktree, so none of them belongs here. The two printing forms touch
//! nothing, but they are not helper-free either: a listing is `git log -g
//! refs/stash` and honors `pager.stash`, and `show` prints the entry's diff,
//! so a configured external diff or textconv driver could run. Callers admit
//! both only once the configuration probe has cleared those helpers.
//!
//! The local-write proof already held these two forms to that bar as the
//! reads beside a `stash apply`. They live here so the ordinary read
//! classifier judges them by the same grammar, instead of a second one.

/// Whether `arguments`, the tokens after the `stash` subcommand, name a
/// printing form.
pub(crate) fn read_form(arguments: &[String]) -> bool {
    let words: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match words.split_first() {
        Some((&"list", rest)) => list(rest),
        Some((&"show", rest)) => show(rest),
        _ => false,
    }
}

/// `stash list` with at most a count limit. Git runs it as `git log -g
/// refs/stash`; other log options can ask for patches whose diff drivers the
/// proof below does not clear.
pub(super) fn list(rest: &[&str]) -> bool {
    match rest {
        [] => true,
        ["-n" | "--max-count", value] => count(value),
        [flag] => flag
            .strip_prefix("--max-count=")
            .or_else(|| flag.strip_prefix('-').filter(|_| !flag.starts_with("--")))
            .is_some_and(count),
        _ => false,
    }
}

/// `stash show` with the diff options that only choose how the entry's diff
/// is printed, and at most one entry. The options an external or textconv
/// driver needs (`--ext-diff`, `--textconv`) are refused, so the read runs
/// only Git's own diff.
pub(super) fn show(rest: &[&str]) -> bool {
    let mut entries = 0;
    rest.iter().all(|option| match *option {
        "-p"
        | "-u"
        | "--patch"
        | "--include-untracked"
        | "--only-untracked"
        | "--stat"
        | "--numstat"
        | "--shortstat"
        | "--name-only"
        | "--name-status"
        | "--summary"
        | "--no-color"
        | "--no-ext-diff"
        | "--no-textconv"
        | "-q"
        | "--quiet" => true,
        entry if entry_name(entry) => {
            entries += 1;
            entries == 1
        }
        _ => false,
    })
}

/// One stash entry: `stash@{N}`, or the bare index Git accepts for it.
pub(super) fn entry_name(value: &str) -> bool {
    let index = value
        .strip_prefix("stash@{")
        .and_then(|rest| rest.strip_suffix('}'))
        .unwrap_or(value);
    !index.is_empty() && index.len() <= 4 && index.bytes().all(|byte| byte.is_ascii_digit())
}

fn count(value: &str) -> bool {
    !value.is_empty() && value.len() <= 6 && value.bytes().all(|byte| byte.is_ascii_digit())
}
