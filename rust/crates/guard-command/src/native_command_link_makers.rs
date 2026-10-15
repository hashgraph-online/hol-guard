//! Programs that can leave a link a later redirect would write through.

use super::command_words;

/// Whether a segment runs a program that makes or moves links. A later
/// redirect can write through such a link, so its literal path no longer
/// names the file. Copies that make or keep links (`cp -l`, `-a`, `-P`, `-d`,
/// `-R`, `--preserve=links`), `ditto`, which keeps links by default, archive
/// or sync tools that recreate them, and Git commands that write a working
/// tree, which may hold committed symlinks, count too. Names are compared
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
    let writes_tree = words().any(|word| {
        matches!(
            word,
            "checkout"
                | "checkout-index"
                | "switch"
                | "restore"
                | "reset"
                | "clone"
                | "worktree"
                | "stash"
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
        )
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
