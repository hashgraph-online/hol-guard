//! Read-only `git` invocations proven without a review.
//!
//! Status, diff, log, show, grep, rev-parse, merge-base, ls-files, `remote -v`, `worktree list`,
//! branch listings, `show-ref`, `for-each-ref`, `rev-list` commit walks, `hash-object`, `config`,
//! `ls-tree` and `cat-file` reads. Diff-style reads that can run a configured helper need the
//! helper-context probe or both `--no-ext-diff` and `--no-textconv`.

#[path = "git_log_names.rs"]
mod log_names;

fn has_argument(arguments: &[String], exact: &[&str], prefixes: &[&str]) -> bool {
    arguments.iter().any(|argument| {
        exact.contains(&argument.as_str())
            || prefixes.iter().any(|prefix| argument.starts_with(prefix))
    })
}

pub(super) fn safe_git_arguments(
    arguments: &[String],
    allow_helper_context: bool,
    context: super::PathContext<'_>,
) -> bool {
    // Branch patterns are ref names, not paths, so only the leading git options
    // (such as -C) go through the path checks.
    if let Some(inspected) =
        crate::command_compatibility::git_inspection_arguments(arguments, context)
    {
        let leading = &arguments[..arguments.len() - inspected.len()];
        let leading_safe = !leading
            .iter()
            .any(|value| value.starts_with(':') || super::sensitive_read_path_argument(value));
        match inspected.split_first() {
            Some((subcommand, rest)) if subcommand == "branch" => {
                return leading_safe && super::git_branch_listing::is_listing(rest);
            }
            // Tag patterns are ref names too, and a listing prints names only.
            Some((subcommand, rest)) if subcommand == "tag" => {
                return leading_safe && super::git_tag_listing::is_listing(rest);
            }
            // The pattern is search text, not a path: only the revisions and
            // pathspecs pass the path screen. Grep pages by default, so the
            // configuration probe has to clear the pager first.
            Some((subcommand, rest)) if subcommand == "grep" => {
                return leading_safe
                    && allow_helper_context
                    && super::git_grep::targets(rest).is_some_and(|targets| {
                        !targets.iter().any(|value| {
                            value.starts_with(':') || super::sensitive_read_path_argument(value)
                        })
                    });
            }
            Some((subcommand, rest)) if subcommand == "hash-object" => {
                return leading_safe
                    && super::git_hash_object::safe_read(rest, allow_helper_context, context);
            }
            _ => {}
        }
    }
    // Git magic pathspec semantics are not proven by this classifier; retain review.
    // A names-only log's glob pathspecs were checked by `log_names` instead.
    // `-S`, `-G` and `--grep` values are search text too.
    let listed = log_names::pathspec_start(arguments, context);
    let search_text = super::git_search_text::pattern_positions(arguments);
    if arguments.iter().enumerate().any(|(index, value)| {
        !search_text.contains(&index)
            && (value.starts_with(':')
                || (super::sensitive_read_path_argument(value)
                    && listed.is_none_or(|start| index < start)))
    }) {
        return false;
    }
    let Some(arguments) =
        crate::command_compatibility::git_inspection_arguments(arguments, context)
    else {
        return false;
    };
    let Some(subcommand) = arguments.first().map(String::as_str) else {
        return false;
    };
    if subcommand == "worktree" {
        return matches!(&arguments[1..], [list] if list == "list")
            || matches!(&arguments[1..], [list, flag] if list == "list" && flag == "--porcelain");
    }
    if subcommand == "merge-base" {
        // Prints commit names only. It still honors pager.merge-base, so the
        // configuration probe has to clear the helper context first.
        return allow_helper_context
            && arguments[1..].iter().all(|argument| {
                !argument.starts_with('-')
                    || matches!(
                        argument.as_str(),
                        "--is-ancestor"
                            | "--all"
                            | "-a"
                            | "--octopus"
                            | "--independent"
                            | "--fork-point"
                    )
            });
    }
    if matches!(subcommand, "ls-tree" | "cat-file") {
        // Object reads honor pager.<name> and can fetch a partial clone's
        // missing objects, so the configuration probe has to clear them first.
        return allow_helper_context
            && super::git_object_reads::read_form(subcommand, &arguments[1..]);
    }
    if matches!(subcommand, "blame" | "describe" | "reflog") {
        // History reads page (pager.blame, pager.reflog, core.pager) and
        // blame converts blobs, so the configuration probe clears them first.
        return allow_helper_context
            && super::git_history_reads::read_form(subcommand, &arguments[1..]);
    }
    if matches!(subcommand, "shortlog" | "check-ignore") {
        // A shortlog pages (pager.shortlog) and both run under the
        // repository's configuration, so the probe clears them first.
        return allow_helper_context
            && super::git_listing_reads::read_form(subcommand, &arguments[1..]);
    }
    if matches!(subcommand, "show-ref" | "for-each-ref") {
        return allow_helper_context
            && super::git_ref_listings::read_form(subcommand, &arguments[1..]);
    }
    if subcommand == "stash" {
        // A stash listing is a log over `refs/stash` and `stash show` runs
        // the diff machinery, so both page and can convert blobs; the
        // configuration probe has to clear those helpers first. Every stash
        // spelling that moves work keeps its own review.
        return allow_helper_context && super::git_stash_reads::read_form(&arguments[1..]);
    }
    if subcommand == "rev-list" {
        // A commit walk honors pager.rev-list and can fetch from a partial
        // clone's promisor, so the configuration probe has to clear it first.
        return allow_helper_context && super::git_rev_list::read_form(&arguments[1..]);
    }
    if subcommand == "config" {
        // Only the configuration probe can prove what the read prints.
        return allow_helper_context
            && super::git_config_reads::read_form(&arguments[1..]).is_some();
    }
    if subcommand == "clean" {
        // A dry run prints the untracked paths it would remove and removes
        // nothing, but reading the index to find them can start a configured
        // `core.fsmonitor`, so the configuration probe clears it first.
        return allow_helper_context && super::git_clean_preview::is_dry_run(&arguments[1..]);
    }
    if subcommand == "apply" {
        // `--check` reports whether the patch would apply and writes nothing,
        // but reading the files it names can start a configured
        // `core.fsmonitor`, so the configuration probe clears it first. Git
        // quotes the line it could not read, so each named patch goes through
        // the ordinary read screen: a workspace name that is a link to a
        // private file is not a patch this proof read.
        return allow_helper_context
            && super::git_apply_check::patch_targets(&arguments[1..]).is_some_and(|patches| {
                patches.iter().all(|patch| {
                    super::read_paths::bounded_file_read_target(
                        patch,
                        context.home_dir,
                        context.cwd,
                    )
                })
            });
    }
    if !matches!(
        subcommand,
        "status" | "diff" | "log" | "show" | "rev-parse" | "ls-files" | "remote"
    ) {
        return false;
    }
    let option_end = arguments
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(arguments.len());
    let active_options = &arguments[1..option_end];
    if subcommand == "remote"
        && arguments
            .get(1)
            .is_some_and(|argument| argument == "get-url")
    {
        // `get-url` prints the configured URL of one remote, which `-v`
        // already prints for every remote.
        let Some((name, options)) = arguments[2..].split_last() else {
            return false;
        };
        return !name.starts_with('-')
            && options
                .iter()
                .all(|option| matches!(option.as_str(), "--push" | "--all"));
    }
    if subcommand == "remote" {
        let has_arguments_after_options = option_end + 1 < arguments.len();
        return !active_options.is_empty()
            && !has_arguments_after_options
            && active_options
                .iter()
                .all(|argument| matches!(argument.as_str(), "-v" | "--verbose"));
    }
    if !allow_helper_context
        && matches!(subcommand, "diff" | "log" | "show")
        && !(active_options
            .iter()
            .any(|argument| argument == "--no-ext-diff")
            && active_options
                .iter()
                .any(|argument| argument == "--no-textconv"))
    {
        return false;
    }
    !has_argument(
        active_options,
        &["--ext-diff", "--textconv", "--output", "-o"],
        &["--output=", "--exec-path="],
    )
}

/// Whether a Git inspection, once the configuration probe cleared its helpers,
/// writes nothing a later Git read could depend on. A pathspec that needs its
/// own read review (a glob that might select a credential file) is judged on
/// that segment; it does not change what the next read runs.
pub(super) fn inspection_writes_nothing(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let Some(inspected) =
        crate::command_compatibility::git_inspection_arguments(arguments, context)
    else {
        return false;
    };
    let leading = &arguments[..arguments.len() - inspected.len()];
    let Some(subcommand) = inspected.first() else {
        return false;
    };
    if !matches!(
        subcommand.as_str(),
        "status" | "diff" | "log" | "show" | "grep" | "merge-base" | "stash"
    ) {
        return false;
    }
    let option_end = inspected
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(inspected.len());
    !has_argument(leading, &[], &["--exec-path"])
        && !has_argument(
            &inspected[1..option_end],
            &["--ext-diff", "--textconv", "--output", "-o"],
            &["--output=", "--exec-path="],
        )
}
