//! Read-only `git` invocations proven without a review.
//!
//! Status, diff, log, show, rev-parse, ls-files, `remote -v`, `worktree list`,
//! branch listings, `hash-object` and `config` reads. Diff-style reads that can run a
//! configured helper need the helper-context probe or both `--no-ext-diff`
//! and `--no-textconv`.

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
            Some((subcommand, rest)) if subcommand == "hash-object" => {
                return leading_safe
                    && super::git_hash_object::safe_read(rest, allow_helper_context, context);
            }
            _ => {}
        }
    }
    // Git magic pathspec semantics are not proven by this classifier; retain review.
    if arguments
        .iter()
        .any(|value| value.starts_with(':') || super::sensitive_read_path_argument(value))
    {
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
    if subcommand == "config" {
        // Only the configuration probe can prove what the read prints.
        return allow_helper_context
            && super::git_config_reads::read_form(&arguments[1..]).is_some();
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
