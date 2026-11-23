use super::{
    executable_basename, safe_directory_target, safe_gh_arguments, safe_git_arguments, safe_reads,
    search, sensitive_path_argument,
};
use crate::CanonicalCommandV1;

#[path = "segment_proof_fresh_checkout.rs"]
mod fresh_checkout;

use fresh_checkout::{fresh_checkout, listing_of_fresh_checkouts, reads_outside_fresh_checkouts};

pub(crate) use super::stderr_merge::without_stderr_merge;

#[path = "segment_proof_cwd.rs"]
mod cwd;
pub(in crate::pretool) use cwd::verified_leading_cd_target;
#[path = "github_metadata_text.rs"]
mod github_metadata_text;
#[path = "jq_filter_text.rs"]
mod jq_filter_text;
pub(super) use cwd::{
    after_read_prefix, cwd_read_executable, exact_safe_absolute_cd_chain, exact_safe_cwd_compound,
    git_read_cwd_compound_context, sequenced_list_cwd_context, verified_cwd_compound_context,
    verified_cwd_list_context,
};

/// The leading `cd <dir>` of a list whose separators leave the steps after it
/// unproven, as the one segment index it covers.
///
/// [`benign_command_segments`] answers nothing at all for such a list: a `;`
/// after the `cd` means a failed `cd` would leave the rest running in the
/// directory the command started in, so no step after it can be proved
/// against the directory the `cd` names. The `cd` is still the first thing
/// that runs, it runs unconditionally, and a verified target neither reads
/// nor creates anything. Proving it alone lets an extension the user allowed
/// cover the programs after it, instead of the whole command keeping a review
/// for the one step nobody doubts.
pub(crate) fn leading_cd_segment(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Vec<usize> {
    // `cd $((PATH=10))` assigns as it expands, so the step the proof reads as
    // a directory change also decides what the programs after it run.
    let assigns = model
        .segments
        .first()
        .is_some_and(|segment| super::shell_arithmetic::arithmetic_assigns(&segment.text));
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        || assigns
        || cwd::verified_leading_cd_target(model, context).is_none()
    {
        return Vec::new();
    }
    vec![0]
}

pub(crate) fn benign_command_segments(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
) -> Vec<usize> {
    segment_proofs(model, context, false, None)
}

/// The segments that would pass as a command of their own, judged as if no
/// other step ran before them.
///
/// [`benign_command_segments`] also asks that every earlier step be proven
/// safe, since an earlier step could change the file a later read opens. A
/// user who explicitly allowed every other step of a compound has answered
/// that question: each step passes alone, so the compound passes. Only the
/// explicit-Allow coverage reads this, after the user's permissions have
/// covered every step that is not proven here.
pub(crate) fn segments_safe_alone(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Vec<usize> {
    segment_proofs(model, context, true, execution_environment)
}

fn segment_proofs(
    model: &CanonicalCommandV1,
    context: super::PathContext<'_>,
    alone: bool,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Vec<usize> {
    let cwd = verified_cwd_compound_context(model, context);
    // A cwd transition changes the meaning of subsequent relative operands.
    // When the transition is not proven -- a `;` after the `cd` leaves the
    // rest running in the starting directory if the `cd` failed -- no later
    // operand can be read against either directory. A step that names no path
    // at all reads the same in both, so judged alone it keeps its proof while
    // everything beside it loses one.
    let unproven_cd_transition = cwd.is_none()
        && model
            .segments
            .iter()
            .any(|segment| segment.executable.as_deref() == Some("cd"));
    if model.confidence != "exact"
        || model.path_overridden
        || !model.wrapper_chain.is_empty()
        // Per-segment sleep proofs must not add up past the whole-command bound.
        || !super::safe_scalar::bounded_total_sleep(model)
        || (unproven_cd_transition && !alone)
    {
        return Vec::new();
    }
    let proof_context = crate::pretool::PathContext {
        literal_words: &[],
        guard_home: context.guard_home,
        home_dir: context.home_dir,
        cdpath_unset: context.cdpath_unset,
        rustup_override_absent: context.rustup_override_absent,
        go_toolchain_inert: context.go_toolchain_inert,
        cargo_config_inert: context.cargo_config_inert,
        npm_config_inert: context.npm_config_inert,
        pip_config_inert: context.pip_config_inert,
        python_environment_inert: context.python_environment_inert,
        shell_home_matches: context.shell_home_matches,
        ripgrep_config_absent: context.ripgrep_config_absent,
        gem_config_absent: context.gem_config_absent,
        http_config_absent: context.http_config_absent,
        openssl_config_absent: context.openssl_config_absent,
        psql_environment: context.psql_environment,
        creates_nothing: super::search::command_creates_nothing(model),
        cwd: if unproven_cd_transition {
            None
        } else {
            cwd.as_deref().or(context.cwd)
        },
    };
    let segment_benign: Vec<bool> = model
        .segments
        .iter()
        .enumerate()
        .map(|(index, segment)| {
            // `$((PATH=10))` assigns while the shell expands this step's own
            // words, before it looks the program up, so the assignment decides
            // what this step runs as well as what the steps after it run.
            // `defaults read $((PATH=1))` runs `1/defaults`, not the macOS
            // program. Screen it on every step, the last one included.
            let assigns = super::shell_arithmetic::arithmetic_assigns(&segment.text);
            (index == 0 && cwd.is_some())
                || (!assigns
                    && exact_safe_segment_with_context(model, segment, false, proof_context))
        })
        .collect();
    let mut all_previous_benign = true;
    let mut tree_may_change = false;
    // The checkouts a proven `git worktree add` of this command creates, each
    // with the repository it checks out. The destination does not exist yet,
    // so the add writes no file a read of another path opens, and the
    // repository is the directory a listing of the destination is screened
    // as below.
    let mut fresh_checkouts: Vec<(std::path::PathBuf, String)> = Vec::new();
    model
        .segments
        .iter()
        .enumerate()
        .filter_map(|(index, original)| {
            // Coverage checks must see the same arguments the proof does. A
            // trailing `2>&1` is not an ls target.
            let stripped = without_stderr_merge(original);
            let segment = stripped.as_ref().unwrap_or(original);
            // A listing of the checkout a proven `git worktree add` of this
            // command creates prints the names the add writes there and opens
            // none of them. Opening a file there keeps its review: the ref
            // decides whether the name is a file or a link out of the
            // checkout.
            let from_new_checkout = alone
                && !fresh_checkouts.is_empty()
                && listing_of_fresh_checkouts(segment, proof_context, &fresh_checkouts);
            let benign = segment_benign[index] || from_new_checkout;
            let basename = executable_basename(segment.executable.as_deref().unwrap_or(""));
            let stdin_filter = stdin_filter_segment(segment);
            let path_free = matches!(
                basename,
                "pwd"
                    | "true"
                    | "exit"
                    | "break"
                    | "continue"
                    | "echo"
                    | "printf"
                    | "which"
                    | "whence"
                    | "whoami"
                    | "uname"
                    | "date"
                    | "sleep"
                    | "uptime"
                    | "pgrep"
                    | "ps"
                    | "lsof"
                    | "pg_isready"
                    | "psql"
            ) || segment.arguments.is_empty()
                || stdin_filter;
            // Context-free public wrappers cannot prove that a file operand or
            // implicit cwd is not a sensitive target. Keep extension consent
            // from upgrading those lexical-only proofs; callers with verified
            // home/cwd context retain the bounded path proof below.
            let requires_path_context = !path_free
                && (super::digest_reads::digest_program(basename)
                    || basename == "openssl"
                    || matches!(
                        basename,
                    "ls" | "cat"
                        | "base64"
                        | "base32"
                        | "dd"
                        | "cp"
                        | "mkdir"
                        | "touch"
                        | "mv"
                        | "ln"
                        | "rm"
                        | "head"
                        | "tail"
                        | "rg"
                        | "grep"
                        | "egrep"
                        | "fgrep"
                        | "sed"
                        | "wc"
                        | "od"
                        | "stat"
                        | "test"
                        | "["
                        | "find"
                        | "du"
                        | "diff"
                        | "cmp"
                        | "file"
                        | "npm"
                        | "jq"
                        | "yq"
                        | "pkill"
                        // A filter given a file operand opens that file, so
                        // its coverage takes the same session proof `cat`
                        // takes. The stdin forms are path-free above.
                        | "sort"
                        | "uniq"
                        | "cut"
                        | "tr"
                        | "paste"
                        | "join"
                        | "column"
                        | "nl"
                        | "tac"
                        | "rev"
                        | "fold"
                        | "expand"
                        | "unexpand"
                        | "fmt"
                        | "comm"
                        | "strings"
                        | "hexdump"
                        | "xxd"
                        | "pr"
                        | "shuf"
                        | "iconv"
                        // A property-list question names the document it reads,
                        // so its coverage takes the same session proof `cat`
                        // takes.
                        | "plutil"
                ))
                // A file operand prints a source line on a syntax error, so it
                // gets the same session proof as `cat`.
                || (matches!(basename, "node" | "nodejs")
                    && segment.arguments.len() == 2
                    && matches!(segment.arguments[0].as_str(), "--check" | "-c"));
            let ls_has_explicit_target = basename != "ls" || {
                let mut skip_next = false;
                let mut found = false;
                for argument in &segment.arguments {
                    if skip_next {
                        skip_next = false;
                        continue;
                    }
                    if matches!(
                        argument.as_str(),
                        "-I" | "--ignore"
                            | "--hide"
                            | "-w"
                            | "--width"
                            | "-T"
                            | "--tabsize"
                            | "--color"
                            | "--sort"
                            | "--format"
                            | "--time"
                            | "--time-style"
                            | "--block-size"
                            | "--quoting-style"
                            | "--indicator-style"
                    ) {
                        skip_next = true;
                        continue;
                    }
                    if !argument.starts_with('-') {
                        found = true;
                        break;
                    }
                }
                found
            };
            // Earlier extension-approved segments may rewrite the tree (checkout/pull);
            // a pre-execution path proof only holds while every predecessor is benign.
            // Judged alone, `ls` with no target lists the working directory,
            // which is proven only when that directory is verified.
            let path_context_verified =
                || safe_reads::verified_path_context(proof_context.home_dir, proof_context.cwd);
            // Reads nothing the working directory decides, so an unproven
            // `cd` before it leaves its answer unchanged. An empty argument
            // list is not enough: a build tool with no arguments still acts
            // on whichever directory it runs in.
            let cwd_independent = stdin_filter
                || matches!(
                    basename,
                    "pwd"
                        | "true"
                        | "exit"
                        | "break"
                        | "continue"
                        | "echo"
                        | "printf"
                        | "whoami"
                        | "uname"
                        | "date"
                        | "sleep"
                        | "uptime"
                );
            let covered = benign
                && (!unproven_cd_transition || cwd_independent)
                && (ls_has_explicit_target || (alone && path_context_verified()))
                && (!requires_path_context || path_context_verified())
                // Judged alone, a file step needs no proven predecessor unless
                // one before it may have changed files (a checkout that swaps
                // a file for a symlink). A step that runs code, such as a
                // container start, still needs every predecessor proven.
                && (path_free
                    || all_previous_benign
                    || (alone
                        && requires_path_context
                        && !tree_may_change
                        && (from_new_checkout
                            || reads_outside_fresh_checkouts(
                                segment,
                                proof_context,
                                &fresh_checkouts,
                            ))));
            all_previous_benign = all_previous_benign && benign;
            if !benign && super::tree_writers::may_rewrite_tree(original) {
                match fresh_checkout(model, index, proof_context, execution_environment) {
                    Some(checkout) => fresh_checkouts.push(checkout),
                    None => tree_may_change = true,
                }
            }
            covered.then_some(index)
        })
        .collect()
}

/// A jq filter may name a `$variable` it binds itself, but the parsed
/// argument does not show whether the shell expands that `$` first:
/// `jq ". as \$x | $x"` reaches jq with whatever `$x` holds spliced into the
/// code. Every `$` in the raw text must be single-quoted or escaped.
fn jq_dollars_literal(segment: &crate::CommandSegmentV1) -> bool {
    super::glob_words::jq_bound_values_literal(segment)
        && (!segment
            .arguments
            .iter()
            .any(|argument| argument.contains('$'))
            || super::shell_literal::literal_everywhere(&segment.text, '$'))
}

/// A later pipeline stage that only filters its standard input.
pub(super) fn stdin_filter_segment(segment: &crate::CommandSegmentV1) -> bool {
    let basename = executable_basename(segment.executable.as_deref().unwrap_or(""));
    segment.pipeline_index > 0
        && ((basename == "cat" && safe_reads::safe_cat_stdin_arguments(&segment.arguments))
            || (matches!(basename, "head" | "tail")
                && safe_reads::safe_head_tail_stdin_arguments(&segment.arguments))
            || (basename == "jq"
                && jq_dollars_literal(segment)
                && safe_reads::safe_jq_stdin_arguments(&segment.arguments))
            || (basename == "wc"
                && safe_reads::safe_word_count_stdin_arguments(&segment.arguments))
            || (basename == "od" && safe_reads::safe_byte_dump_stdin_arguments(&segment.arguments))
            || (super::digest_reads::digest_program(basename)
                && super::digest_reads::safe_digest_stdin_arguments(&segment.arguments))
            || (matches!(basename, "grep" | "egrep" | "fgrep")
                && search::safe_grep_stdin_arguments(
                    &segment.arguments,
                    &super::listing_reads::literal_words(&segment.text),
                ))
            || (basename == "rg"
                && search::safe_rg_stdin_arguments(
                    &segment.arguments,
                    &super::listing_reads::literal_words(&segment.text),
                ))
            || (basename == "sed" && safe_reads::safe_sed_stdin_arguments(&segment.arguments))
            || super::stdin_filters::safe_arguments(basename, &segment.arguments))
}

/// Whether no other step of the command line could create a file, directory or
/// link before this one runs. A recursive walk of a name that is not there
/// reads nothing, but only while the name stays missing, so the proof of an
/// absent operand rests on this.
fn no_peer_creates(model: &CanonicalCommandV1, segment: &crate::CommandSegmentV1) -> bool {
    model
        .segments
        .iter()
        .filter(|other| other.span != segment.span)
        .all(search::grep::creates_nothing)
}

pub(super) fn exact_safe_segment_with_context(
    model: &CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    allow_git_helper_context: bool,
    context: super::PathContext<'_>,
) -> bool {
    let stripped = without_stderr_merge(segment);
    let segment = stripped.as_ref().unwrap_or(segment);
    let Some(executable) = segment.executable.as_deref() else {
        // A list item such as `OUT=build/report.json` runs no program: it binds
        // shell variables and returns, so there is nothing to attribute and
        // nothing to execute. The same screen the compatibility pass uses keeps
        // the values literal and the names ordinary, so no setting here steers
        // lookup, loading, configuration or credentials for a later item. Each
        // later item still carries its own proof, with the literal projected
        // into it, and a redirect would write a file rather than bind a name.
        // A glob the binding holds is listed wherever a later bare `$NAME`
        // expands it, so it takes that listing's proof here.
        return segment.pipeline_index == 0
            && !segment.text.contains(['<', '>'])
            && crate::command_compatibility::sets_ordinary_variables(segment)
            && super::glob_words::bound_globs_listable(
                segment,
                super::glob_words::binding_values(&segment.tokens),
                context,
            );
    };
    let basename = executable_basename(executable);
    // `jq` and `yq` both take an expression that selects fields inside the
    // document they read, so the words in it are not names on this machine.
    let filter_expression = match basename {
        "jq" => safe_reads::jq_filter_position(&segment.arguments, segment.pipeline_index > 0),
        "yq" => super::yaml_query_reads::expression_position(&segment.arguments),
        _ => None,
    };
    // The same proof the admission arm runs below, so a search segment that
    // arm refuses cannot shed its sensitive-text screen here.
    let inert_search = match basename {
        "grep" | "egrep" | "fgrep" => search::grep::safe_grep_segment(model, segment, context),
        "rg" => search::safe_rg_segment(model, segment, context),
        // A fan-out is deliberately absent here. The proof below bounds the
        // walk to regular source files under the working directory, but it
        // reads nothing about the name the walk matches, so `fd -H -t f -e
        // txt id_rsa -x cat` would otherwise shed the screen that keeps the
        // same pattern reviewed as a plain search -- and as `find ... -exec`,
        // which this arm has never carried either.
        "fd" => search::safe_fd_segment(model, segment, context),
        _ => false,
    };
    let search_text = if basename == "git" {
        super::git_search_text::pattern_positions(&segment.arguments)
    } else {
        Vec::new()
    };
    let secret_namespace = github_metadata_text::secret_namespace(segment);
    // A `kubectl` output template selects fields in the object the read
    // returns, so its words are not names on this machine.
    let output_templates = super::kubectl_reads::output_template_positions(segment);
    let sensitive_text = secret_namespace
        .map(|index| github_metadata_text::without_namespace(segment, index))
        .or_else(|| super::kubectl_reads::without_templates(segment, &output_templates))
        .or_else(|| {
            filter_expression.and_then(|index| jq_filter_text::without_jq_filter(segment, index))
        });
    if (!inert_search
        && !super::source_file_read_segment(segment)
        && super::git_search_text::segment_sensitive(model, segment, sensitive_text, context.cwd))
        || (!matches!(basename, "rg" | "grep" | "egrep" | "fgrep" | "fd")
            && segment
                .arguments
                .iter()
                .enumerate()
                .any(|(index, argument)| {
                    Some(index) != filter_expression
                        && Some(index) != secret_namespace
                        && !output_templates.contains(&index)
                        && !search_text.contains(&index)
                        && sensitive_path_argument(argument)
                }))
        || !(segment.environment_names.is_empty()
            || super::inert_environment::inert_prefix(segment)
            || (basename == "kubectl"
                && super::kubectl_reads::trusted_kubeconfig_prefix(segment, context)))
        || (executable.contains(['/', '\\'])
            && !super::postgres_reads::trusted_pg_ctl_path(executable, context)
            && !super::guard_diagnostics::guard_install_executable(executable, context)
            && !super::venv_program_path::environment_program(executable, context)
            && !super::installed_program_path::installed_program(segment, executable, context))
    {
        return false;
    }
    if (super::host_facts::safe_host_fact(basename, &segment.arguments)
        // `expr` prints its operands, in the result or in the error naming
        // the next one, and a `seq` separator is printed between the bounds,
        // so an unquoted glob in either reaches the terminal the way `echo`'s
        // does and is screened by the same listing proof.
        && (!matches!(basename, "expr" | "seq")
            || super::glob_words::printed_globs_listable(model, segment, context)))
        || super::version_probes::safe_version_probe(basename, &segment.arguments)
        || super::network_facts::safe_network_fact(basename, &segment.arguments)
        || super::status_facts::safe_status_fact(basename, &segment.arguments)
        || super::help_probes::safe_help_probe(basename, &segment.arguments, context)
        || super::liveness_probes::safe_liveness_probe(basename, &segment.arguments)
        || super::property_list_reads::safe_property_list_read(
            basename,
            &segment.arguments,
            context,
        )
        || super::preference_reads::safe_preference_read(basename, &segment.arguments)
        || super::manager_usage::safe_manager_segment(basename, model, segment, context)
    {
        return true;
    }
    match basename {
        "cd" => {
            model.segments.len() == 1
                && matches!(segment.arguments.as_slice(), [target] if safe_directory_target(target))
                && super::directory_targets::drive_targets_quoted(segment)
        }
        // `printf -v NAME` and `%n` assign a shell variable rather than print.
        "pwd" | "true" | "echo" | "printf" | "whoami" | "uname" => {
            !super::printf_words::printf_sets_variable(segment)
                && !super::control_flow_flatten::command_word_changes_shell_state(&segment.text)
                && super::glob_words::printed_globs_listable(model, segment, context)
        }
        "exit" => super::shell_flow::safe_exit_arguments(&segment.arguments),
        "break" | "continue" => super::shell_flow::safe_loop_control_arguments(&segment.arguments),
        "unset" | "set" => super::inert_environment::safe_shell_setting(basename, segment),
        // zsh's builtin `which` can print a function or alias definition.
        // Unqualified `whence` and its `-a` / `-v` forms can do likewise;
        // only explicit `whence -p` with bounded names proves a path lookup.
        // Neither is eligible for the generic harmless-command fast path.
        "type" | "command" | "whence" | "which" => {
            super::lookup_reads::safe_path_lookup(basename, &segment.arguments)
        }
        // `go version` and a read-only `go env` print and exit, but which
        // toolchain prints them is decided first; `go_toolchain` reads that
        // choice.
        "go" => {
            // A peer step may create go.mod/go.work after the filesystem
            // proof and before Go selects a toolchain from PATH.
            no_peer_creates(model, segment)
                && super::go_toolchain::safe_go_probe(&segment.arguments, context)
        }
        "cargo" => super::rust_toolchain::safe_cargo_probe(&segment.arguments, context),
        "rustc" => super::rust_toolchain::safe_version_probe(&segment.arguments, context),
        "date" => safe_reads::safe_date_arguments(&segment.arguments),
        "sleep" => safe_reads::safe_sleep_arguments(&segment.arguments),
        "uptime" => segment.arguments.is_empty(),
        "printenv" => super::safe_scalar::safe_printenv_arguments(&segment.arguments),
        "pgrep" => super::safe_scalar::safe_pgrep_arguments(&segment.arguments),
        "ps" => super::safe_scalar::safe_ps_arguments(&segment.arguments),
        "launchctl" => super::safe_scalar::safe_launchctl_arguments(&segment.arguments),
        "lsof" => super::safe_scalar::safe_lsof_arguments(&segment.arguments),
        "pkill" => super::process_stops::safe_pkill_arguments(&segment.arguments, context),
        // Signal 0 is delivered to nothing. The kernel performs the
        // permission check and returns, so `kill -0 4821` answers whether a
        // process is still there and leaves it running -- the same question
        // `ps -p 4821` asks, which is proven here already. A wait on a build
        // or a server asks it on every pass, and the containment reading
        // already admits this exact form for the same reason. An expansion
        // stands for a number by the time the arguments are read, so
        // `kill -0 $((-1))` would arrive as the pid `1` while the shell
        // signals every process the user can reach; the operands this form
        // admits are the words the caller wrote, so a segment carrying one
        // is not among them.
        "kill" => {
            !segment.text.contains('$')
                && super::workspace_contained::kill::liveness_only(&segment.arguments)
        }
        "pg_isready" => super::safe_scalar::safe_pg_isready_arguments(&segment.arguments),
        "ls" => super::listing_reads::safe_listing_segment(
            &segment.text,
            &segment.arguments,
            context,
            no_peer_creates(model, segment),
        ),
        "tree" => super::tree_reads::safe_tree_segment(
            &segment.arguments,
            context,
            no_peer_creates(model, segment),
        ),
        "test" => {
            safe_reads::safe_file_predicate_arguments(&segment.arguments, &segment.text, context)
        }
        "[" => segment
            .arguments
            .split_last()
            .is_some_and(|(last, predicate)| {
                last == "]"
                    && safe_reads::safe_file_predicate_arguments(predicate, &segment.text, context)
            }),
        "find" => {
            super::find_reads::safe_find_listing_arguments(&segment.arguments, context)
                || super::fanout_reads::safe_find_exec(model, segment, context)
        }
        "xargs" => {
            super::fanout_reads::safe_xargs(model, segment, context)
                || super::fanout_reads::safe_listing_xargs(model, segment, context)
                || super::fanout_reads::safe_git_xargs(model, segment, context)
        }
        // Operand-free `cat` after a pipe only copies the proven producer's output.
        "cat" => {
            (segment.pipeline_index > 0 && safe_reads::safe_cat_stdin_arguments(&segment.arguments))
                || safe_reads::safe_plain_file_arguments(&segment.arguments, context)
        }
        "base64" | "base32" => {
            super::base64_reads::safe_base64_arguments(&segment.arguments, context)
                || (segment.pipeline_index > 0
                    && super::stdin_filters::safe_arguments(basename, &segment.arguments))
        }
        "dd" => super::dd_reads::safe_dd_arguments(&segment.arguments, context),
        "du" => super::metadata_reads::safe_du_arguments(&segment.arguments, context),
        "df" => super::metadata_reads::safe_df_arguments(&segment.arguments),
        "diff" => super::metadata_reads::safe_diff_arguments(segment, context),
        "cmp" => super::metadata_reads::safe_cmp_arguments(segment, context),
        "file" => super::metadata_reads::safe_file_arguments(&segment.arguments, context),
        "stat" => super::metadata_reads::safe_stat_arguments(&segment.arguments, context),
        "unzip" => super::archive_listing::safe_unzip_arguments(&segment.arguments, context),
        "zipinfo" => super::archive_listing::safe_zipinfo_arguments(&segment.arguments, context),
        "xattr" => super::archive_listing::safe_xattr_arguments(&segment.arguments, context),
        "dirname" | "basename" => {
            super::path_word_reads::safe_path_word_arguments(basename, &segment.arguments)
                && super::glob_words::printed_globs_listable(model, segment, context)
        }
        "readlink" | "realpath" => super::path_word_reads::safe_resolved_path_arguments(
            basename,
            &segment.arguments,
            context,
        ),
        "cp" => {
            super::chain_temporary::copy_segments_allowed(model, segment, context)
                && super::directory_targets::drive_targets_quoted(segment)
                && (safe_reads::safe_copy_arguments_into(
                    &segment.arguments,
                    context,
                    &super::chain_temporary::created_scratch_directories(model, context),
                ) || super::recursive_copy::safe_recursive_copy_arguments(
                    &segment.arguments,
                    context,
                ))
        }
        "mktemp" | "mkdir" | "touch" | "mv" | "ln" | "rm" => {
            let alone = basename != "ln" || model.segments.len() == 1;
            (model.segments.len() == 1
                || (matches!(basename, "mkdir" | "touch")
                    && super::chain_temporary::creation_chain(model))
                || (basename == "mkdir" && super::chain_temporary::mkdir_chain(model))
                || (matches!(basename, "mkdir" | "touch" | "rm")
                    && super::chain_temporary::removal_chain(model, context))
                || (basename == "ln" && super::symlink_writes::link_chain(model, context)))
                && (basename != "ln" && basename != "rm"
                    || super::directory_targets::home_targets_unquoted(segment))
                // In a chain the link must join two checkouts of one
                // repository; a link to any readable source is proven alone.
                && ((alone
                    && safe_reads::safe_file_mutation_arguments(basename, &segment.arguments, context))
                    // A session run from the directory above its checkouts can
                    // still share a dependency directory between two of them.
                    || (basename == "ln"
                        && super::symlink_writes::safe_symlink_arguments(segment, context)))
        }
        // Admit stdin only when every producer in the pipeline is also proven safe.
        "head" | "tail" => safe_reads::safe_head_tail_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
            basename == "tail",
        ),
        "git" => {
            safe_git_arguments(&segment.arguments, allow_git_helper_context, context)
                && super::directory_targets::drive_targets_quoted(segment)
                && super::directory_targets::home_targets_unquoted(segment)
        }
        "gh" => safe_gh_arguments(&segment.arguments, &segment.text),
        "curl" => super::curl_reads::safe_curl_segment(model, segment, context),
        "http" | "xh" => super::http_reads::safe_http_segment(basename, model, segment, context),
        "wget" => super::wget_reads::safe_wget_segment(model, segment, context),
        "kubectl" => super::kubectl_reads::safe_kubectl_segment(model, segment, context),
        "export" => {
            (super::kubectl_reads::safe_export_segment(model, segment, context)
                || super::inert_environment::safe_shell_setting(basename, segment))
                && super::glob_words::bound_globs_listable(
                    segment,
                    super::glob_words::binding_values(&segment.arguments),
                    context,
                )
        }
        "wrangler" => super::wrangler_reads::safe_wrangler_arguments(&segment.arguments),
        "doctl" => super::doctl_reads::safe_doctl_arguments(&segment.arguments),
        "docker" => super::docker_reads::safe_docker_segment(model, segment),
        "helm" => super::helm_usage::safe_helm_segment(model, segment),
        n if super::port_probes::proves(n) => super::port_probes::safe(n, model, segment, context),
        "brew" => super::brew_reads::safe_brew_segment(model, segment),
        "gem" => super::gem_reads::safe_gem_segment(model, segment, context),
        "pg_ctl" => super::postgres_reads::safe_pg_ctl_arguments(&segment.arguments),
        "psql" => super::postgres_reads::safe_psql_arguments(&segment.arguments, context),
        "sqlite3" => super::sqlite_reads::safe_sqlite3_arguments(&segment.arguments, context),
        "npm" => {
            super::npm_reads::read_only_neighbors(model, "npm")
                && super::npm_reads::safe_npm_read(&segment.arguments, context)
        }
        "pnpm" => {
            super::npm_reads::read_only_neighbors(model, "pnpm")
                && super::pnpm_reads::safe_pnpm_read(&segment.arguments, context)
        }
        "pip" | "pip3" => super::pip_reads::safe_pip_segment(model, segment, context),
        "uv" => super::tool_inventory_reads::safe_uv_segment(model, segment),
        "pipx" => super::tool_inventory_reads::safe_pipx_segment(model, segment),
        // Windows spells the same launcher with its program suffix, and the
        // install screen above already strips one before it decides, so the
        // two spellings have to reach the same proof. `hol-guard.cmd`, the
        // desktop PATH shim, is deliberately absent: a batch target is run
        // through `cmd.exe /c`, which reads the arguments a second time, and
        // the text `command test` carries exists to hold the operators that
        // reading would act on. The spelling is handed on, because on Windows
        // the one without a suffix reaches that same shim through `PATHEXT`
        // and the proof has to read its arguments as the shim would.
        "hol-guard" | "hol-guard.exe" => {
            super::guard_home_option::safe_hol_guard_segment(basename, segment, context)
        }
        "jq" => {
            jq_dollars_literal(segment)
                && ((segment.pipeline_index > 0
                    && safe_reads::safe_jq_piped_arguments(&segment.arguments, context))
                    || (segment.pipeline_index == 0
                        && safe_reads::safe_jq_file_arguments(&segment.arguments, context)))
        }
        "yq" => {
            jq_dollars_literal(segment)
                && ((segment.pipeline_index > 0
                    && super::yaml_query_reads::safe_yaml_query_piped_arguments(
                        &segment.arguments,
                        context,
                    ))
                    || (segment.pipeline_index == 0
                        && super::yaml_query_reads::safe_yaml_query_file_arguments(
                            &segment.arguments,
                            context,
                        )))
        }
        "wc" => safe_reads::safe_word_count_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "od" => safe_reads::safe_byte_dump_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        // An unquoted Windows drive path loses its backslashes to the shell,
        // so the file `openssl` opens is not the one the proof screened.
        "openssl" => {
            super::directory_targets::drive_targets_quoted(segment)
                && super::digest_reads::safe_openssl_digest_arguments(
                    &segment.arguments,
                    segment.pipeline_index > 0,
                    context,
                )
        }
        name if super::digest_reads::digest_program(name) => {
            super::digest_reads::safe_digest_arguments(
                &segment.arguments,
                segment.pipeline_index > 0,
                context,
            )
        }
        // `numfmt` takes numbers, not files. Its operands are the numbers it
        // rewrites, and it reads standard input when it is given none, so a
        // file name there is an invalid number rather than a read. Proving
        // the operands as files would claim a read that never happens and
        // would leave the ordinary `numfmt --to=iec 1048576` under review.
        "numfmt" => super::stdin_filters::safe_number_arguments(&segment.arguments),
        name if super::stdin_filters::text_filter_program(name) => {
            (segment.pipeline_index > 0
                && super::stdin_filters::safe_arguments(basename, &segment.arguments))
                || super::stdin_filters::safe_file_arguments(basename, &segment.arguments, context)
        }
        "rg" | "grep" | "egrep" | "fgrep" | "fd" => {
            (match basename {
                "grep" | "egrep" | "fgrep" => {
                    search::grep::safe_grep_segment(model, segment, context)
                }
                "rg" => search::safe_rg_segment(model, segment, context),
                _ => {
                    search::safe_fd_segment(model, segment, context)
                        || super::fanout_reads::safe_fd_exec(model, segment, context)
                }
            }) && super::directory_targets::search_home_targets_safe(
                segment,
                context.cwd,
                context.home_dir,
            )
        }
        "sed" => {
            safe_reads::safe_sed_arguments(&segment.arguments, segment.pipeline_index > 0, context)
                || super::sed_edits::safe_in_place_segment(model, segment, context)
        }
        // A proof admits a file writer only as the whole command.
        "rustfmt" => {
            model.segments.len() == 1
                && super::rustfmt_writes::safe_rustfmt_arguments(&segment.arguments, context)
        }
        "awk" => super::awk_reads::safe_awk_arguments(
            &segment.arguments,
            segment.pipeline_index > 0,
            context,
        ),
        "python" | "python3" | "node" | "nodejs" => {
            super::safe_scalar::version_probe_arguments(basename, &segment.arguments)
                || super::python_filter::inline_program(basename, model, segment, context)
                || (matches!(basename, "node" | "nodejs")
                    && super::safe_scalar::node_syntax_check_arguments(
                        &segment.arguments,
                        segment.pipeline_index > 0,
                        context,
                    ))
        }
        _ => false,
    }
}
