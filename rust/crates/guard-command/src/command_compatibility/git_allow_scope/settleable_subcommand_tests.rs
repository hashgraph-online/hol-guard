//! What `SETTLEABLE_SUBCOMMANDS` holds, and the reason each name is in
//! it or out of it.

use super::SETTLEABLE_SUBCOMMANDS;

fn settles(name: &str) -> bool {
    SETTLEABLE_SUBCOMMANDS.contains(&name)
}

#[test]
fn the_list_is_sorted_and_holds_each_name_once() {
    let mut sorted = SETTLEABLE_SUBCOMMANDS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.as_slice(), SETTLEABLE_SUBCOMMANDS);
}

#[test]
fn plumbing_that_only_reads_or_writes_this_repository_settles() {
    // A user who allows Git means Git. Porcelain and the plumbing under
    // it are the same program reading the same objects.
    for name in [
        "whatchanged",
        "ls-tree",
        "cat-file",
        "rev-list",
        "diff-tree",
        "show-index",
        "verify-pack",
        "verify-commit",
        "verify-tag",
        "fsck",
        "count-objects",
        "version",
    ] {
        assert!(settles(name), "{name} should settle under a Git Allow");
    }
}

#[test]
fn aliases_settle_wherever_the_name_they_alias_does() {
    for (alias, porcelain) in [
        ("stage", "add"),
        ("fsck-objects", "fsck"),
        ("pickaxe", "blame"),
        ("whatchanged", "log"),
    ] {
        assert_eq!(
            settles(alias),
            settles(porcelain),
            "{alias} and {porcelain} are the same built-in"
        );
    }
}

#[test]
fn write_plumbing_settles_because_the_floors_around_it_stay() {
    // These write no more than `commit`, `reset`, `checkout` and `rm`,
    // which already settle. The path and history-loss floors are what
    // hold them, and an Allow does not lift those.
    for name in [
        "update-ref",
        "update-index",
        "commit-tree",
        "write-tree",
        "read-tree",
        "hash-object",
        "pack-refs",
        "prune",
    ] {
        assert!(settles(name), "{name} should settle under a Git Allow");
    }
}

#[test]
fn a_built_in_that_reaches_past_this_repository_keeps_its_review() {
    for name in [
        // Starts a program the user configured rather than Git.
        "credential",
        "credential-store",
        "difftool",
        "mergetool",
        "hook",
        "remote-ext",
        "remote-fd",
        "instaweb",
        "send-email",
        "filter-branch",
        "help",
        "p4",
        "svn",
        // Serves or consumes whatever a peer sends.
        "upload-pack",
        "upload-archive",
        "receive-pack",
        "send-pack",
        "fetch-pack",
        "fast-import",
        "daemon",
        "http-backend",
        "shell",
        // Keeps running, or installs a schedule.
        "fsmonitor--daemon",
        "maintenance",
        // Packages configuration and environment into a report.
        "bugreport",
        "diagnose",
        // Runs a further Git command this contract never read.
        "for-each-repo",
        "submodule--helper",
        // Rewrites history wholesale.
        "replay",
        // Runs a program named on its own command line.
        "merge-index",
        // Writes to a destination no floor here reads.
        "bundle",
        "checkout-index",
        "checkout--worker",
        "index-pack",
        "mailinfo",
        "mailsplit",
        "merge-file",
        "pack-objects",
        // Spells a command whose floors read only the other spelling.
        "init-db",
    ] {
        assert!(!settles(name), "{name} should keep its review");
    }
}
