// Git runs a `diff.<driver>.textconv` program only while it prints patch
// text or searches content (pickaxe). Stat, name and raw formats, logs
// without patches and non-verbose status read blobs directly, so a driver,
// such as the one every Git for Windows install configures, cannot run.
// Any option not listed here is treated as one that may print a patch.

/// `options` are the arguments before `--` that start with `-`.
pub(super) fn may_run(operation: &str, options: &[&str]) -> bool {
    let known = |option: &&str| inert(option) || summary_format(option);
    match operation {
        // Verbose status prints the staged diff.
        "status" => options.iter().any(|option| status_verbose(option)),
        "log" => !options.iter().all(known),
        // Both print a patch unless a summary format replaces it.
        "diff" | "show" => {
            !(options.iter().any(|option| summary_format(option)) && options.iter().all(known))
        }
        // grep honors textconv only with --textconv, which its read proof
        // refuses.
        "branch" | "hash-object" | "config" | "grep" => false,
        // Only the plain object-read forms, which never convert, reach the probe.
        // Reference listings and commit walks print names and object ids only.
        "ls-tree" | "cat-file" | "show-ref" | "for-each-ref" | "rev-list" => false,
        // describe prints a ref name; reflog prints the ref log's own entries.
        // blame is absent on purpose: it converts the blob it annotates.
        "describe" | "reflog" => false,
        _ => true,
    }
}

fn status_verbose(option: &str) -> bool {
    match option.strip_prefix("--") {
        // Git accepts any unambiguous prefix, and `verbose` is the only long
        // status option starting with `v`.
        Some(name) => {
            let name = name.split('=').next().unwrap_or(name);
            !name.is_empty() && "verbose".starts_with(name)
        }
        // No other short status option or `-u` mode value contains `v`.
        None => option.get(1..).is_some_and(|flags| flags.contains('v')),
    }
}

fn summary_format(option: &str) -> bool {
    matches!(
        option,
        "--stat"
            | "--numstat"
            | "--shortstat"
            | "--name-only"
            | "--name-status"
            | "--raw"
            | "--check"
            | "--summary"
            | "--compact-summary"
            | "--dirstat"
            | "--no-patch"
            | "-s"
    ) || ["--stat=", "--dirstat="]
        .iter()
        .any(|prefix| option.starts_with(prefix))
}

fn inert(option: &str) -> bool {
    if let Some(count) = option
        .strip_prefix("-n")
        .or_else(|| option.strip_prefix('-'))
    {
        if !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit()) {
            return true;
        }
    }
    matches!(
        option,
        "-n" | "--oneline"
            | "--graph"
            | "--decorate"
            | "--no-decorate"
            | "--abbrev-commit"
            | "--no-abbrev-commit"
            | "--color"
            | "--no-color"
            | "--all"
            | "--branches"
            | "--tags"
            | "--remotes"
            | "--reverse"
            | "--first-parent"
            | "--merges"
            | "--no-merges"
            | "--topo-order"
            | "--date-order"
            | "--relative-date"
            | "--cached"
            | "--staged"
            | "--no-textconv"
            | "--no-ext-diff"
            | "--no-renames"
            | "--follow"
            | "--pretty"
    ) || [
        "--max-count=",
        "--skip=",
        "--format=",
        "--pretty=",
        "--decorate=",
        "--abbrev=",
        "--color=",
        "--date=",
        "--since=",
        "--until=",
        "--after=",
        "--before=",
        "--author=",
        "--committer=",
        "--grep=",
        "--branches=",
        "--tags=",
        "--remotes=",
    ]
    .iter()
    .any(|prefix| option.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::may_run;

    #[test]
    fn plain_status_and_summaries_cannot_run_textconv() {
        for (operation, options) in [
            ("status", &[][..]),
            ("status", &["-s", "-b", "-uno", "--porcelain=v2"][..]),
            ("diff", &["--stat"][..]),
            ("diff", &["--cached", "--name-only"][..]),
            ("show", &["--stat", "--format=%h %s"][..]),
            ("show", &["-s"][..]),
            ("log", &[][..]),
            ("log", &["-1", "--oneline"][..]),
            ("log", &["-n5", "--stat", "--no-merges"][..]),
            ("branch", &["-vv"][..]),
        ] {
            assert!(!may_run(operation, options), "{operation} {options:?}");
        }
    }

    #[test]
    fn patches_pickaxe_and_verbose_status_can_run_textconv() {
        for (operation, options) in [
            ("status", &["-v"][..]),
            ("status", &["-sv"][..]),
            ("status", &["--verb"][..]),
            ("diff", &[][..]),
            ("diff", &["--stat", "-p"][..]),
            ("diff", &["--word-diff"][..]),
            ("show", &[][..]),
            ("show", &["--textconv"][..]),
            ("log", &["-p"][..]),
            ("log", &["-1", "--cc"][..]),
            ("log", &["-Sneedle", "--oneline"][..]),
            ("log", &["-G", "--oneline"][..]),
            ("log", &["--stat", "--unknown-option"][..]),
        ] {
            assert!(may_run(operation, options), "{operation} {options:?}");
        }
    }
}
