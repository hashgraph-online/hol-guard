//! Read-only `git` invocations proven without a review.
//!
//! Status, diff, log, `whatchanged`, `range-diff`, show, grep, rev-parse, merge-base, ls-files,
//! `remote -v`, `worktree list`, branch listings, `show-ref`, `for-each-ref`, `rev-list` commit
//! walks, `hash-object`, `config`, `ls-tree`, `cat-file` and `sparse-checkout list` reads.
//! Diff-style reads that can run a configured helper need the helper-context probe or both
//! `--no-ext-diff` and `--no-textconv`.

#[path = "git_log_names.rs"]
mod log_names;

fn has_argument(arguments: &[String], exact: &[&str], prefixes: &[&str]) -> bool {
    arguments.iter().any(|argument| {
        exact.contains(&argument.as_str())
            || prefixes.iter().any(|prefix| argument.starts_with(prefix))
    })
}

/// The long options that name a program for Git to run or a file for Git to
/// write, as this module refuses them.
const REFUSED_LONG_OPTIONS: &[&str] = &["--ext-diff", "--output", "--textconv"];

/// Whether the word names one of those options, written in full or as any
/// prefix of one.
///
/// Git's own parser resolves an unambiguous prefix to the option that owns
/// it, so `--textc` starts the program a `diff.<driver>.textconv` setting
/// names and `--ext-d` the one `diff.external` names, while `--no-textconv`
/// and `--no-ext-diff` on the same line still satisfy the pair asked for
/// above. A screen that compares whole words lets both past.
///
/// `--text` is left in: the comparison verbs spell it in full for their own
/// "treat the file as text", and Git resolves an exact spelling to the
/// option that owns it rather than reading it as a prefix of another.
///
/// [`crate::contained_git::names_helper_or_output`] asks the same question
/// of the containment route. It is kept separate because it answers per verb
/// from that route's own table, and the verbs admitted here -- `status`,
/// `ls-files`, `remote`, `rev-parse` -- are not in it.
fn names_refused_option(word: &str) -> bool {
    let name = word.split('=').next().unwrap_or(word);
    if name == "-o" {
        return true;
    }
    if !name.starts_with("--") || name.len() < 3 || name == "--text" {
        return false;
    }
    REFUSED_LONG_OPTIONS
        .iter()
        .any(|option| option.starts_with(name))
}

/// Whether `value`, a `git grep` target, is a tracked document whose name
/// only reads like a credential, such as a committed
/// `command.kubernetes-secrets.json`. A leading option other than the pager
/// switch can move Git elsewhere, so a relative target is proven only
/// without one.
fn tracked_target(value: &str, leading: &[String], context: super::PathContext<'_>) -> bool {
    (std::path::Path::new(value).is_absolute()
        || leading
            .iter()
            .all(|option| matches!(option.as_str(), "--no-pager" | "-P")))
        && !super::sensitive_path_argument(value)
        && super::search_scope_tracked::names::resolves_to_tracked(value, context.cwd)
}

/// A plain exclusion pathspec after `--`: `:!name`, `:^name` or
/// `:(exclude)name`. An exclusion only removes paths from what the read
/// prints. With no other pathspec Git reads as if none were given, so the
/// read never covers more than it would without the exclusion, and the path
/// it names is never opened. Any further magic (`:!/name`, `:(exclude,glob)`)
/// and a value before `--`, where Git may read it as an index object name,
/// keep the review.
fn exclusion_pathspec(arguments: &[String], index: usize) -> bool {
    let value = arguments[index].as_str();
    let path = value
        .strip_prefix(":!")
        .or_else(|| value.strip_prefix(":^"))
        .or_else(|| value.strip_prefix(":(exclude)"));
    arguments[..index].iter().any(|argument| argument == "--")
        && path.is_some_and(|path| !path.is_empty() && !path.starts_with([':', '/', '!', '^', '(']))
}

/// A pathspec after `--` that names a sign-in or token feature directory
/// inside the repository, such as `src/api/auth`, or a directory or document
/// below one. Git filters the read to that part of the tree, which an
/// unfiltered read already covers, and the credential-name screen refused it
/// only for the directory's name. `--no-index` compares files on disk rather
/// than tracked content, so it keeps the review.
fn feature_pathspec(arguments: &[String], index: usize, context: super::PathContext<'_>) -> bool {
    let Some(separator) = arguments[..index]
        .iter()
        .rposition(|argument| argument == "--")
    else {
        return false;
    };
    // Git switches to its filesystem comparison mode when any pathspec names
    // an object outside the worktree, even without an explicit `--no-index`.
    // The feature-directory exemption only covers tracked repository reads.
    let filesystem_comparison = arguments[separator + 1..].iter().any(|argument| {
        let path = std::path::Path::new(argument);
        argument.starts_with('~')
            || path.is_absolute()
            || path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
    });
    !filesystem_comparison
        && !arguments.iter().any(|argument| argument == "--no-index")
        && crate::command_compatibility::git_operand_directory(arguments, context).is_some_and(
            |directory| {
                super::read_paths::feature_directories::feature_pathspec(
                    &directory,
                    &arguments[index],
                    context.home_dir,
                )
            },
        )
}

pub(super) fn safe_git_arguments(
    arguments: &[String],
    allow_helper_context: bool,
    context: super::PathContext<'_>,
) -> bool {
    // The inspected slice replaces `arguments` below, so the route the
    // leading options name is kept here.
    let with_route = arguments;
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
            // The pattern `--get-regexp` matches names keys in the
            // configuration file. Git never expands it over the files that
            // are there, so `remote.*url` is not a glob that could select a
            // private file, and the path screen that refuses every such
            // pattern does not apply to it. Each remaining argument is still
            // screened: the shell expands an unquoted one before Git sees it,
            // and `git config *` in a directory holding `user.name` and
            // `value` reaches Git as the write `git config user.name value`.
            // Only the configuration probe can prove what the read prints.
            Some((subcommand, rest)) if subcommand == "config" => {
                return leading_safe
                    && allow_helper_context
                    && !super::git_config_reads::screened_arguments(rest)
                        .iter()
                        .any(|value| {
                            value.starts_with(':') || super::sensitive_read_path_argument(value)
                        })
                    && super::git_config_reads::read_form(rest).is_some();
            }
            // The pattern is search text, not a path: only the revisions and
            // pathspecs pass the path screen. Grep pages by default, so the
            // configuration probe has to clear the pager first.
            Some((subcommand, rest)) if subcommand == "grep" => {
                return leading_safe
                    && allow_helper_context
                    && super::git_grep::targets(rest).is_some_and(|targets| {
                        // The tracked proof reads the working-tree file, so it
                        // covers only pathspecs Git searches there: after a
                        // `--` with no revision before it, and without
                        // `--cached`, which searches the index instead.
                        let working_tree = targets.first().is_some_and(|first| first == "--")
                            && !rest.iter().any(|argument| argument == "--cached");
                        !targets.iter().any(|value| {
                            value.starts_with(':')
                                || (super::sensitive_read_path_argument(value)
                                    && !(working_tree && tracked_target(value, leading, context)))
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
    // A names-only log's or `ls-files` glob pathspecs were checked by
    // `log_names` instead.
    // `-S`, `-G` and `--grep` values are search text too.
    let listed = log_names::pathspec_start(arguments, context);
    let search_text = super::git_search_text::pattern_positions(arguments);
    // A replacement listing's pattern is matched against the refs under
    // `refs/replace/`, not expanded over the files that are there.
    let replacement = super::git_side_record_reads::listing_pattern_position(arguments, context);
    let index_objects = super::git_listing_reads::index_stage_object_positions(arguments, context);
    if arguments.iter().enumerate().any(|(index, value)| {
        !search_text.contains(&index)
            && replacement != Some(index)
            && !exclusion_pathspec(arguments, index)
            && ((value.starts_with(':') && !index_objects.contains(&index))
                || (super::sensitive_read_path_argument(value)
                    && listed.is_none_or(|start| index < start)
                    && !feature_pathspec(arguments, index, context)))
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
    if matches!(subcommand, "blame" | "annotate" | "describe" | "reflog") {
        // History reads page (pager.blame, pager.reflog, core.pager) and
        // blame converts blobs, so the configuration probe clears them first.
        return allow_helper_context
            && super::git_history_reads::read_form(subcommand, &arguments[1..]);
    }
    if matches!(
        subcommand,
        "shortlog" | "check-ignore" | "count-objects" | "check-attr" | "fsck" | "sparse-checkout"
    ) {
        // A shortlog pages (pager.shortlog) and all of them run under the
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
    if subcommand == "submodule" {
        // A status line is printed from the superproject, whose index it
        // reads, so a configured `core.fsmonitor` there can start and the
        // configuration probe has to clear it first. The recursive walk,
        // which reads each submodule's own configuration, and every verb
        // that moves work keep their own review.
        return allow_helper_context && super::git_submodule_reads::read_form(&arguments[1..]);
    }
    if matches!(subcommand, "bisect" | "notes" | "replace") {
        // A bisect log, a note and the replacement refs print through the
        // pager (core.pager), so the configuration probe has to clear it
        // first. Every spelling of any of the three that moves a ref, runs a
        // program or opens the editor keeps its own review.
        return allow_helper_context
            && super::git_side_record_reads::read_form(subcommand, &arguments[1..]);
    }
    if subcommand == "rev-list" {
        // A commit walk honors pager.rev-list and can fetch from a partial
        // clone's promisor, so the configuration probe has to clear it first.
        return allow_helper_context && super::git_rev_list::read_form(&arguments[1..]);
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
    if matches!(subcommand, "name-rev" | "show-branch" | "check-ref-format") {
        // None of the three starts a pager of its own, runs a configured
        // driver or opens a working-tree file, but an explicit `pager.<verb>`
        // key can still name a program, so the configuration probe clears
        // that first.
        return allow_helper_context;
    }
    if matches!(subcommand, "var" | "patch-id" | "stripspace") {
        // `var` prints a logical variable, and the other two filter the text
        // on their stdin. None opens a working-tree file or runs a configured
        // driver, but an explicit `pager.<verb>` key can still name a
        // program, so the configuration probe clears that first.
        return allow_helper_context;
    }
    if subcommand == "check-mailmap" {
        // Translating contacts reads the repository's own mailmap. The
        // options that name another file or object keep their review.
        return allow_helper_context
            && crate::command_compatibility::git_mailmap_read(&arguments[1..]);
    }
    if subcommand == "interpret-trailers" {
        // The pipe-only spelling prints the message it was handed.
        // `--in-place` and a file operand open the path instead and keep
        // their review.
        return allow_helper_context
            && crate::command_compatibility::git_trailers_read(&arguments[1..]);
    }
    if subcommand == "symbolic-ref" {
        // Printing where a symbolic ref points reads one loose file. A second
        // operand writes that ref instead and keeps its own review; the
        // explicit `pager.symbolic-ref` key is the probe's to clear.
        return allow_helper_context
            && crate::command_compatibility::git_symbolic_ref_read(&arguments[1..]);
    }
    if !matches!(
        subcommand,
        "status"
            | "cherry"
            | "diff"
            | "diff-files"
            | "diff-index"
            | "diff-tree"
            | "log"
            | "whatchanged"
            | "range-diff"
            | "show"
            | "rev-parse"
            | "ls-files"
            | "remote"
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
    if subcommand == "remote" && arguments.get(1).is_some_and(|argument| argument == "show") {
        // `show -n` prints what the configuration already holds about a
        // remote and says so: `-n` is the switch that keeps Git from asking
        // the remote itself, so the command stays inside the repository.
        // Without it Git opens the connection, which is a different question
        // than a read of the local configuration.
        let (names, options): (Vec<&String>, Vec<&String>) = arguments[2..]
            .iter()
            .partition(|argument| !argument.starts_with('-'));
        return !options.is_empty()
            && options.iter().all(|option| option.as_str() == "-n")
            && names.len() <= 1;
    }
    if subcommand == "remote" {
        // Bare `git remote` prints the configured names, which `-v` already
        // prints beside their URLs.
        let has_arguments_after_options = option_end + 1 < arguments.len();
        return !has_arguments_after_options
            && active_options
                .iter()
                .all(|argument| matches!(argument.as_str(), "-v" | "--verbose"));
    }
    // These read through the diff machinery, so without the configuration
    // probe only the spelling that turns the external driver and the
    // textconv filter off is proven. That pair is the whole helper surface
    // of a comparison between two trees, and nothing more.
    //
    // A commit walk reads past it. `log.showSignature`, a `%G` placeholder
    // and a `pretty.*` alias carrying one each start the configured
    // verification program, and neither switch touches that setting;
    // `range-diff` also assembles an inner `git log -p` and passes neither
    // switch down to it, so a configured `diff.<driver>.textconv` still runs
    // with both of them on the command line. The walks are therefore proven
    // by the probe, which screens all of it, and never by the pair alone.
    //
    // A `-C` route that discovers no
    // repository needs neither: Git dies in its own setup before it reads a
    // diff, textconv, pager or filter setting, so there is no configured
    // helper for the options to turn off. `git cherry` runs no helper of its
    // own, but it still prints under `pager.cherry`, so it asks for the same
    // clearance and has no spelling of its own that answers instead: the two
    // diff switches are not options it defines.
    let helpers_off = !super::git_history_reads::verifies_signatures(subcommand)
        && active_options
            .iter()
            .any(|argument| argument == "--no-ext-diff")
        && active_options
            .iter()
            .any(|argument| argument == "--no-textconv");
    let diff_family = matches!(
        subcommand,
        "diff"
            | "diff-files"
            | "diff-index"
            | "diff-tree"
            | "log"
            | "whatchanged"
            | "range-diff"
            | "show"
    );
    if (diff_family || subcommand == "cherry")
        && !(allow_helper_context
            || (diff_family && helpers_off)
            || super::git_helper_context::arguments_route_to_no_repository(with_route, context))
    {
        return false;
    }
    !active_options
        .iter()
        .any(|argument| names_refused_option(argument))
        && !has_argument(active_options, &[], &["--exec-path="])
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
        "status"
            | "cherry"
            | "diff"
            | "diff-files"
            | "diff-index"
            | "diff-tree"
            | "log"
            | "whatchanged"
            | "range-diff"
            | "show"
            | "grep"
            | "merge-base"
            | "stash"
            | "name-rev"
            | "show-branch"
            | "check-ref-format"
            | "symbolic-ref"
            | "var"
            | "patch-id"
            | "stripspace"
            | "check-mailmap"
            | "interpret-trailers"
    ) {
        return false;
    }
    let option_end = inspected
        .iter()
        .position(|argument| argument == "--")
        .unwrap_or(inspected.len());
    !has_argument(leading, &[], &["--exec-path"])
        && !inspected[1..option_end]
            .iter()
            .any(|argument| names_refused_option(argument))
        && !has_argument(&inspected[1..option_end], &[], &["--exec-path="])
}

#[cfg(test)]
#[path = "git_reads_change_listing_tests.rs"]
mod change_listing_tests;

#[cfg(test)]
#[path = "git_reads_config_pattern_tests.rs"]
mod config_pattern_tests;

#[cfg(test)]
#[path = "git_reads_option_name_tests.rs"]
mod option_name_tests;

#[cfg(test)]
mod feature_pathspec_tests {
    use super::feature_pathspec;
    use crate::pretool::PathContext;
    use std::path::{Path, PathBuf};

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/git-feature-pathspec-tests")
                .join(std::process::id().to_string());
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join(".git")).unwrap();
            std::fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
            std::fs::create_dir_all(root.join("src/lib/auth")).unwrap();
            std::fs::write(root.join("src/lib/auth/README.md"), "source\n").unwrap();
            Self(root)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn context(root: &Path) -> PathContext<'_> {
        let cwd = root.to_str();
        PathContext {
            cwd,
            ..PathContext::default()
        }
    }

    #[test]
    fn feature_pathspec_refuses_an_implicit_no_index_sibling_comparison() {
        let fixture = Fixture::new();
        let arguments = ["diff", "--", "src/lib/auth", "../reference"].map(str::to_owned);
        assert!(!feature_pathspec(&arguments, 2, context(&fixture.0)));
    }

    #[test]
    fn feature_pathspec_refuses_a_shell_home_sibling_comparison() {
        let fixture = Fixture::new();
        let arguments = ["diff", "--", "src/lib/auth", "~/scratch"].map(str::to_owned);
        assert!(!feature_pathspec(&arguments, 2, context(&fixture.0)));
    }

    #[test]
    fn feature_pathspec_keeps_an_in_repository_pathspec_read() {
        let fixture = Fixture::new();
        let arguments = ["diff", "--", "src/lib/auth", "README.md"].map(str::to_owned);
        assert!(feature_pathspec(&arguments, 2, context(&fixture.0)));
    }
}
