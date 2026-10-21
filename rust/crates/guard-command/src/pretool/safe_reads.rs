#[path = "command_sequences.rs"]
mod command_sequences;
#[path = "jq_filter.rs"]
mod jq_filter;
#[path = "read_globs.rs"]
mod read_globs;
pub(super) use super::directory_targets::verified_cwd_target;
pub(super) use super::read_paths::{
    bounded_file_read_target, bounded_omp_directory_read_target, bounded_omp_file_read_target,
    bounded_omp_selector_requires_review, bounded_read_target, bounded_structured_file_read_target,
    missing_read_target, safe_read_target, verified_path_context,
};
pub(super) use super::safe_scalar::{safe_date_arguments, safe_sleep_arguments};
pub(crate) use super::safe_writes::plan_note_write_sources;
pub(super) use super::safe_writes::{
    bounded_native_file_write_target, bounded_structured_file_write_target,
    safe_copy_arguments_into, safe_file_mutation_arguments,
};
pub(crate) use command_sequences::proven_created_file_removal;
pub(super) use command_sequences::{exact_safe_sequence, leading_and_cd, leading_semicolon_cd};
pub(super) use read_globs::glob_file_matches;

pub(super) fn safe_file_predicate_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let [predicate, target] = arguments else {
        return false;
    };
    // Each predicate reads only the target's metadata: its type, permission
    // bits or size. `-x` is also true for a directory the caller may enter.
    verified_path_context(context.home_dir, context.cwd)
        && matches!(predicate.as_str(), "-f" | "-d" | "-e" | "-r" | "-x" | "-s")
        && !target.starts_with('-')
        && (bounded_read_target(
            target,
            context.home_dir,
            context.cwd,
            matches!(predicate.as_str(), "-d" | "-e" | "-x"),
        ) || metadata_only_target(target, context))
}

/// A target a read screen holds back although the predicate returns nothing
/// the screen protects.
///
/// `test -f ~/work/kubeconfig.digitalocean && …` is how a script decides
/// whether it has the file it was written for. What comes back is one bit
/// about that file, the same bit `ls` already prints for it, so a name that
/// reads like a credential's is no reason to hold the question back. The
/// store the credential is actually kept in is not admitted either way: the
/// listing rule answers for a file whose directory a read may already name.
///
/// A predicate is as often asked about a path that is not there yet, so an
/// unresolvable target is the ordinary case here rather than a spelling the
/// screens could not follow. A listing answers that question too, with the
/// bounds it needs: every missing component visible, and the nearest
/// existing ancestor a directory this context may name.
fn metadata_only_target(target: &str, context: super::PathContext<'_>) -> bool {
    super::tool_bin_listing::credential_file_metadata_operand(target, context)
        || super::listing_reads::absent_listing_operand(target, context)
}

pub(super) fn safe_listing_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    arguments.iter().all(|argument| {
        if argument == "-" || argument == "-R" || argument == "--recursive" {
            return false;
        }
        if argument.starts_with('-') {
            return !argument.contains('R');
        }
        (command_read_target(argument, context, true)
            && !super::search::skill_link_resolves_over_home(argument, context))
            || super::search::agent_root_listing(argument, context, false)
            || super::read_paths::repository_hidden_directory(
                argument,
                context.home_dir,
                context.cwd,
            )
            || super::read_paths::home_hidden_directory(argument, context.home_dir, context.cwd)
            || (super::search::skill_listing_root(argument, context)
                && !super::search::skill_link_resolves_over_home(argument, context))
            || super::listing_reads::absent_listing_operand(argument, context)
            || super::tool_bin_listing::tool_bin_listing_operand(argument, context)
            || super::tool_bin_listing::node_bin_listing_operand(argument, context)
            || super::tool_bin_listing::credential_file_metadata_operand(argument, context)
            || super::tool_bin_listing::global_package_listing_operand(argument, context)
    })
}

pub(super) fn command_read_target(
    value: &str,
    context: super::PathContext<'_>,
    allow_directory: bool,
) -> bool {
    if context.home_dir.is_some() || context.cwd.is_some() {
        bounded_read_target(value, context.home_dir, context.cwd, allow_directory)
            || (!allow_directory && read_globs::bounded_glob_file_read_target(value, context))
            || (!allow_directory
                && super::chain_temporary::absent_temporary_read_target(
                    value,
                    context.home_dir,
                    context.cwd,
                ))
            || (!allow_directory
                && super::read_paths::home_hidden_content_read(
                    value,
                    context.home_dir,
                    context.cwd,
                ))
            || (!allow_directory && super::search::safe_literal_bracket_read_target(value, context))
            // `grep` and `rg` already open a file named inside a repository
            // beside the session's own through this screen, including a name
            // that is not there yet: an agent spells one whenever it guesses
            // at a manifest. A reader that prints the file instead of
            // matching inside it reads no more than they do, and reading an
            // absent path prints an error, as it already does for a name
            // guessed inside the workspace.
            || (!allow_directory
                && super::search::sibling_repository_named_file(value, context, true))
    } else {
        safe_read_target(value)
    }
}

/// Leading `-n`, `-E` and `-r` flags (alone or joined, as in `-nE`), then one
/// script or one or more `-e SCRIPT` pairs, then the targets.
fn sed_programs_and_targets(arguments: &[String]) -> Option<(bool, Vec<&str>, &[String])> {
    let mut quiet = false;
    let mut rest = arguments;
    while let Some((flag, tail)) = rest.split_first() {
        let Some(letters) = flag.strip_prefix('-').filter(|letters| {
            !letters.is_empty() && letters.bytes().all(|b| matches!(b, b'n' | b'E' | b'r'))
        }) else {
            break;
        };
        quiet |= letters.contains('n');
        rest = tail;
    }
    let mut programs = Vec::new();
    if rest.first().is_some_and(|arg| arg == "-e") {
        while let [flag, program, tail @ ..] = rest {
            if flag != "-e" {
                break;
            }
            programs.push(program.as_str());
            rest = tail;
        }
    } else {
        let (program, targets) = rest.split_first()?;
        programs.push(program.as_str());
        rest = targets;
    }
    if programs.is_empty() {
        return None;
    }
    Some((quiet, programs, rest))
}

pub(super) fn safe_sed_stdin_arguments(arguments: &[String]) -> bool {
    let Some((_, _, targets)) = sed_programs_and_targets(arguments) else {
        return false;
    };
    (targets.is_empty() || matches!(targets, [target] if target == "-"))
        && safe_sed_arguments(arguments, true, super::PathContext::default())
}

/// Upper bound on `;`-separated range prints in one `sed -n` program.
const MAX_PRINT_RANGES: usize = 16;

pub(super) fn safe_sed_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    let Some((quiet, programs, targets)) = sed_programs_and_targets(arguments) else {
        return false;
    };
    if programs
        .iter()
        .any(|program| program.len() > 256 || program.contains(['\n', '\r']))
    {
        return false;
    }
    // `1,12p;28,40p` prints several line ranges, as the Codex output proof
    // already allows, and `-e 5p -e 9p` is the same program. Every statement
    // must be a numeric or `$` range print, so no w/W/e/r command, label or
    // regex address can join it.
    let statements: Vec<&str> = programs
        .iter()
        .flat_map(|program| program.split(';'))
        .collect();
    let bounded_print = quiet
        && statements.len() <= MAX_PRINT_RANGES
        && statements
            .iter()
            .all(|statement| bounded_print_statement(statement));
    // Exactly one substitution with inert flags. No e/w commands, program
    // files, in-place edits, or additional statements can enter this proof.
    let substitution = !quiet
        && matches!(programs.as_slice(), [program]
        if !program.contains(';')
            && program.strip_prefix("s/").is_some_and(|body| {
                let parts: Vec<_> = body.split('/').collect();
                parts.len() == 3 && matches!(parts[2], "" | "g")
            }));
    (bounded_print || substitution)
        && (matches!(targets, [target] if (target == "-" && piped_input) || (!target.starts_with('-') && command_read_target(target, context, false)))
            || (targets.is_empty() && piped_input))
}

/// One `sed -n` statement that only names lines: `5p`, `$p`, `36,39p`,
/// `36, 39p`. A range with no command, such as `36,37`, is a sed syntax error
/// that prints nothing, so it reads no more than the print does.
fn bounded_print_statement(statement: &str) -> bool {
    let statement = statement.trim_matches([' ', '\t']);
    let range = statement
        .strip_suffix('p')
        .unwrap_or(statement)
        .trim_end_matches([' ', '\t']);
    let counts: Vec<_> = range.split(',').collect();
    (1..=2).contains(&counts.len())
        && counts.iter().all(|count| {
            let count = count.trim_matches([' ', '\t']);
            count == "$"
                || (!count.is_empty()
                    && count.len() <= 6
                    && count.bytes().all(|byte| byte.is_ascii_digit())
                    && count.parse::<u32>().is_ok_and(|count| count > 0))
        })
}

/// Upper bound on `cat` file operands. Each operand needs its own path proof,
/// so this only keeps the per-command proof cost bounded.
const MAX_PLAIN_FILE_TARGETS: usize = 16;

/// `cat a b` reads exactly what `cat a; cat b` reads, so every operand gets the
/// same single-file proof instead of sending multi-file reads to review.
pub(super) fn safe_plain_file_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let mut targets = 0usize;
    let mut after_options = false;
    for argument in arguments {
        if after_options {
            if argument == "-" || !command_read_target(argument, context, false) {
                return false;
            }
            targets += 1;
            continue;
        }
        if argument == "--" {
            after_options = true;
            continue;
        }
        if argument == "-" || argument.starts_with("--") {
            return false;
        }
        if argument.starts_with('-') {
            if argument.bytes().skip(1).all(|byte| {
                matches!(
                    byte,
                    b'A' | b'b' | b'E' | b'e' | b'n' | b's' | b'T' | b't' | b'u' | b'v'
                )
            }) {
                continue;
            }
            return false;
        }
        if !command_read_target(argument, context, false) {
            return false;
        }
        targets += 1;
    }
    (1..=MAX_PLAIN_FILE_TARGETS).contains(&targets)
}

/// `cat -A`, `cat -n` and the like after a pipe: only display flags, no file
/// operand, so it copies the proven producer's output and reads nothing else.
pub(super) fn safe_cat_stdin_arguments(arguments: &[String]) -> bool {
    arguments.iter().all(|argument| {
        argument.strip_prefix('-').is_some_and(|flags| {
            !flags.is_empty()
                && flags.bytes().all(|byte| {
                    matches!(
                        byte,
                        b'A' | b'b' | b'E' | b'e' | b'n' | b's' | b'T' | b't' | b'u' | b'v'
                    )
                })
        })
    })
}

pub(super) fn safe_head_tail_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    safe_head_tail_with_targets(arguments, piped_input, context, true)
}

pub(super) fn safe_head_tail_stdin_arguments(arguments: &[String]) -> bool {
    safe_head_tail_with_targets(
        arguments,
        true,
        crate::pretool::PathContext::default(),
        false,
    )
}

pub(super) fn safe_word_count_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    safe_word_count_with_targets(arguments, piped_input, context, true)
}

pub(super) fn safe_word_count_stdin_arguments(arguments: &[String]) -> bool {
    safe_word_count_with_targets(arguments, true, super::PathContext::default(), false)
}

pub(super) fn safe_byte_dump_arguments(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
) -> bool {
    safe_byte_dump_with_targets(arguments, piped_input, context, true)
}

pub(super) fn safe_byte_dump_stdin_arguments(arguments: &[String]) -> bool {
    safe_byte_dump_with_targets(arguments, true, super::PathContext::default(), false)
}

fn safe_byte_dump_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
    allow_targets: bool,
) -> bool {
    let mut options = true;
    let mut target = false;
    for argument in arguments {
        if options && argument == "--" {
            options = false;
            continue;
        }
        if options
            && matches!(
                argument.as_str(),
                "-a" | "-b"
                    | "-c"
                    | "-d"
                    | "-f"
                    | "-o"
                    | "-s"
                    | "-v"
                    | "-x"
                    | "-An"
                    | "-Ad"
                    | "-Ao"
                    | "-Ax"
                    | "-tc"
                    | "-tx1"
            )
        {
            continue;
        }
        if target {
            return false;
        }
        if argument == "-" {
            if !piped_input {
                return false;
            }
        } else if argument.starts_with('-')
            || !allow_targets
            || !verified_path_context(context.home_dir, context.cwd)
            || !command_read_target(argument, context, false)
        {
            return false;
        }
        options = false;
        target = true;
    }
    target || piped_input
}

fn safe_word_count_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
    allow_targets: bool,
) -> bool {
    let mut operands = false;
    let mut separator = false;
    let mut saw_target = false;
    for argument in arguments {
        if !operands && argument == "--" {
            operands = true;
            separator = true;
            continue;
        }
        if !operands && argument.starts_with('-') && argument != "-" {
            let counting_option = matches!(
                argument.as_str(),
                "--bytes" | "--chars" | "--lines" | "--words" | "--max-line-length"
            ) || argument.strip_prefix('-').is_some_and(|flags| {
                !flags.is_empty()
                    && flags
                        .bytes()
                        .all(|flag| matches!(flag, b'c' | b'm' | b'l' | b'w' | b'L'))
            });
            if !counting_option {
                return false;
            }
            continue;
        }
        operands = true;
        if argument == "-" {
            if !piped_input {
                return false;
            }
        } else if !allow_targets
            || (argument.starts_with('-') && !separator)
            || !command_read_target(argument, context, false)
        {
            return false;
        }
        saw_target = true;
    }
    saw_target || piped_input
}

/// `jq <filter> <file>` reads one bounded file through the same filter
/// grammar the stdin form admits.
pub(super) fn safe_jq_file_arguments(
    arguments: &[String],
    context: super::PathContext<'_>,
) -> bool {
    let Some((file, rest)) = arguments.split_last() else {
        return false;
    };
    !file.starts_with('-')
        && safe_jq_filter_arguments(rest)
        && command_read_target(file, context, false)
}

/// Where a proven jq filter sits: last when jq reads stdin, before the file
/// operand otherwise. The filter is a program over the value read, so a
/// field such as `.key` is not a path to screen.
pub(super) fn jq_filter_position(arguments: &[String], piped_input: bool) -> Option<usize> {
    let last = arguments.len().checked_sub(1)?;
    let index = if piped_input {
        last
    } else {
        last.checked_sub(1)?
    };
    if piped_input && !arguments[index].starts_with('.') {
        return None;
    }
    jq_filter::safe_filter(&arguments[index]).then_some(index)
}

pub(super) fn safe_jq_stdin_arguments(arguments: &[String]) -> bool {
    // Stdin may come from a network/API command, so retain the pre-existing
    // projection-first requirement. Standalone builtins and object output are
    // admitted only when jq reads a separately screened file operand.
    arguments
        .last()
        .is_some_and(|filter| filter.starts_with('.'))
        && safe_jq_filter_arguments(arguments)
}

fn safe_jq_filter_arguments(arguments: &[String]) -> bool {
    let mut filter = None;
    for argument in arguments {
        if filter.is_none()
            && matches!(
                argument.as_str(),
                "-r" | "-c"
                    | "-e"
                    | "-M"
                    | "--raw-output"
                    | "--compact-output"
                    | "--exit-status"
                    | "--monochrome-output"
            )
        {
            continue;
        }
        if filter.replace(argument.as_str()).is_some() {
            return false;
        }
    }
    let Some(filter) = filter else { return false };
    jq_filter::safe_filter(filter)
}

/// A head/tail count: `20`, or `+31` for "from line 31" (`tail -n +31`).
fn head_tail_count(value: &str) -> bool {
    let digits = value.strip_prefix('+').unwrap_or(value);
    !digits.is_empty() && digits.len() <= 6 && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn safe_head_tail_with_targets(
    arguments: &[String],
    piped_input: bool,
    context: super::PathContext<'_>,
    allow_target: bool,
) -> bool {
    let mut saw_target = false;
    let mut expect_count = false;
    let mut after_options = false;
    for argument in arguments {
        if expect_count {
            if !head_tail_count(argument) {
                return false;
            }
            expect_count = false;
            continue;
        }
        if after_options {
            if !allow_target
                || argument == "-"
                || !command_read_target(argument, context, false)
                || saw_target
            {
                return false;
            }
            saw_target = true;
            continue;
        }
        if argument == "--" {
            after_options = true;
            continue;
        }
        if matches!(argument.as_str(), "-n" | "--lines" | "-c" | "--bytes") {
            expect_count = true;
            continue;
        }
        if let Some(value) = argument
            .strip_prefix("--lines=")
            .or_else(|| argument.strip_prefix("--bytes="))
        {
            if !head_tail_count(value) {
                return false;
            }
            continue;
        }
        // `-20`, and the attached `-n+31` and `-c10` spellings.
        if let Some(value) = argument.strip_prefix('-') {
            if value.strip_prefix(['n', 'c']).is_some_and(head_tail_count)
                || (!value.starts_with('+') && head_tail_count(value))
            {
                continue;
            }
        }
        // Bare `+N` is a filename on modern GNU head/tail. Never skip the
        // read-target proof; `-n +N` remains an option/value pair above.
        if argument.starts_with('-') {
            return false;
        }
        if !allow_target || !command_read_target(argument, context, false) {
            return false;
        }
        if saw_target {
            return false;
        }
        saw_target = true;
    }
    (saw_target || piped_input) && !expect_count
}

#[cfg(test)]
mod jq_stdin_boundary_tests {
    use super::{jq_filter_position, safe_jq_filter_arguments, safe_jq_stdin_arguments};

    #[test]
    fn object_filters_and_bare_builtins_do_not_expand_stdin_authority() {
        for filter in ["keys", "length", "{tests: .tests, total: .total}"] {
            let args = vec!["-r".to_owned(), filter.to_owned()];
            assert!(safe_jq_filter_arguments(&args), "{filter}");
            assert!(!safe_jq_stdin_arguments(&args), "{filter}");
            assert_eq!(jq_filter_position(&args, true), None, "{filter}");
        }
        let projection = vec!["-r".to_owned(), ".tests | keys".to_owned()];
        assert!(safe_jq_stdin_arguments(&projection));
        assert_eq!(jq_filter_position(&projection, true), Some(1));
    }
}

#[cfg(test)]
mod head_tail_plus_filename_tests {
    use super::*;

    #[test]
    fn a_bare_plus_number_is_a_file_operand_not_a_line_count() {
        let root = env!("CARGO_MANIFEST_DIR");
        let context = super::super::PathContext {
            home_dir: Some(root),
            cwd: Some(root),
            ..Default::default()
        };
        assert!(!safe_head_tail_with_targets(
            &["+31".to_owned(), "Cargo.toml".to_owned()],
            false,
            context,
            true
        ));
        // A nonexistent +31 filename by itself can be a harmless proven
        // missing-file read; the security invariant is that it still occupies
        // the target slot and cannot hide an additional source operand.
        assert!(safe_head_tail_with_targets(
            &["-n".to_owned(), "+31".to_owned(), "Cargo.toml".to_owned()],
            false,
            context,
            true
        ));
    }
}
