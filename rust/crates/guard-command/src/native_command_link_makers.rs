//! Programs that can leave a link a later redirect would write through.

use super::command_words;

/// Whether a segment runs a program that makes or moves links. A later
/// redirect can write through such a link, so its literal path no longer
/// names the file. Copies that make or keep links (`cp -l`, `-a`, `-P`, `-d`,
/// `-R`, `--preserve=links`), `ditto`, which keeps links by default, archive
/// or sync tools that recreate them, and Git commands that write a working
/// tree, which may hold committed symlinks, count too. So does `--ext-diff`
/// on any Git command: it runs the program `diff.external` names, which is
/// free to leave a link behind whatever the subcommand itself does. Names are
/// compared
/// case-insensitively without `.exe` or `.cmd`, and any `--sy` option is
/// taken as GNU's abbreviation of `--symbolic-link`.
pub(super) fn creates_links(literal: &str) -> bool {
    let words = || literal.split_whitespace();
    let link_copy = words().any(|word| {
        word.starts_with("--sy")
            || matches!(
                word,
                "--archive" | "--no-dereference" | "--recursive" | "--link"
            )
            || word
                .strip_prefix("--preserve=")
                .is_some_and(|list| list.split(',').any(|item| matches!(item, "links" | "all")))
            || (word.starts_with('-')
                && !word.starts_with("--")
                && word.contains(['s', 'a', 'P', 'd', 'r', 'R', 'l']))
    });
    let listed: Vec<&str> = words().collect();
    let writes_tree = listed.iter().enumerate().any(|(index, word)| {
        matches!(
            *word,
            "checkout"
                | "checkout-index"
                | "switch"
                | "restore"
                | "reset"
                | "clone"
                | "pull"
                | "merge"
                | "rebase"
                | "cherry-pick"
                | "revert"
                | "apply"
                | "am"
                | "read-tree"
                | "sparse-checkout"
                | "submodule"
                | "mv"
                | "bisect"
        ) || *word == "--ext-diff"
            || group_writes_tree(word, listed.get(index + 1).copied())
    });
    command_words(literal).any(|word| {
        let base = word.rsplit(['/', '\\']).next().unwrap_or(word);
        let lowered = base.to_ascii_lowercase();
        let name = lowered
            .strip_suffix(".exe")
            .or_else(|| lowered.strip_suffix(".cmd"))
            .unwrap_or(&lowered);
        matches!(
            name,
            "ln" | "gln"
                | "link"
                | "mklink"
                | "mv"
                | "gmv"
                | "tar"
                | "gtar"
                | "bsdtar"
                | "unzip"
                | "cpio"
                | "pax"
                | "7z"
                | "rsync"
                | "ditto"
        ) || (link_copy && matches!(name, "cp" | "gcp"))
            || (writes_tree && name == "git")
    })
}

/// Whether a Git subcommand group lays down a working tree. `worktree` and
/// `stash` each name several operations, and only some of them write files:
/// `git worktree add` and `git stash pop` do, while `git worktree list` and
/// `git stash list` only report what already exists. Counting the group word
/// alone made every one of them a link maker, so an ordinary file write beside
/// `git worktree list` lost its literal redirect and failed evaluation. The
/// operation that follows the group decides; one that is missing or not named
/// here keeps the group counted as a tree write. `git stash show` takes diff
/// options, but an `--ext-diff` among them is caught by the caller's own check
/// before the operation is read.
fn group_writes_tree(word: &str, operation: Option<&str>) -> bool {
    let reports = match word {
        "worktree" => ["list", "prune", "remove", "lock", "unlock"].as_slice(),
        "stash" => ["list", "show", "drop", "clear"].as_slice(),
        _ => return false,
    };
    operation.is_none_or(|operation| !reports.contains(&operation))
}
