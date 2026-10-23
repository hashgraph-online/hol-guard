use super::{
    options, short_search_option, sibling, tree, unsafe_search_value, ReadContext, SearchValueRole,
};
use crate::pretool::search_pattern_clearance::PatternClearance;

/// Which missing operands a proof may accept.
#[derive(Clone, Copy)]
struct AbsentOperands {
    plain: bool,
    recursive: bool,
}

/// The operand proof alone, as if `grep` were the whole command.
pub(super) fn safe_grep_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    let absent = AbsentOperands {
        plain: true,
        recursive: true,
    };
    safe_arguments(arguments, context, false, absent)
}

/// A `grep` segment inside its command. A missing operand is proven only
/// while it stays missing: no other segment may create a file, directory or
/// link there (`ln -s <dir> <repo>/cfg && grep -rn . <repo>/cfg/` reads through
/// the fresh link). A recursive search walks whatever appears at a missing
/// root, so it accepts one only beside `cd` and downstream stdin filters.
pub(crate) fn safe_grep_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: ReadContext<'_>,
) -> bool {
    let others: Vec<&crate::CommandSegmentV1> = model
        .segments
        .iter()
        .filter(|other| other.span != segment.span)
        .collect();
    let absent = AbsentOperands {
        plain: others.iter().all(|other| creates_nothing(other, false)),
        recursive: others.iter().all(|other| creates_nothing(other, true)),
    };
    safe_arguments(&segment.arguments, context, false, absent)
}

/// A peer that cannot create a filesystem entry: no output redirect beyond
/// `/dev/null`, and a command that only prints, filters or changes directory.
/// `strict` admits only `cd` and stdin filters after a pipe.
pub(super) fn creates_nothing(segment: &crate::CommandSegmentV1, strict: bool) -> bool {
    let text = ["2>&1", "2>/dev/null", ">/dev/null"]
        .iter()
        .fold(segment.text.clone(), |text, quiet| text.replace(quiet, ""));
    if text.contains('>') || !segment.wrapper_chain.is_empty() || segment.path_overridden {
        return false;
    }
    match segment.executable.as_deref() {
        Some("cd") => true,
        Some(_) if strict => {
            segment.pipeline_index > 0
                && crate::pretool::segment_proof::stdin_filter_segment(segment)
        }
        Some(executable) => matches!(
            executable,
            "cat"
                | "cut"
                | "diff"
                | "echo"
                | "egrep"
                | "fgrep"
                | "grep"
                | "head"
                | "jq"
                | "ls"
                | "nl"
                | "printf"
                | "pwd"
                | "rg"
                | "tail"
                | "test"
                | "tr"
                | "true"
                | "wc"
        ),
        None => false,
    }
}

pub(super) fn safe_stdin_arguments(arguments: &[String]) -> bool {
    let absent = AbsentOperands {
        plain: false,
        recursive: false,
    };
    safe_arguments(
        arguments,
        crate::pretool::PathContext::default(),
        true,
        absent,
    )
}

fn safe_arguments(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    absent: AbsentOperands,
) -> bool {
    arguments_pass(arguments, context, stdin_only, absent, false)
}

mod reach;
pub(in crate::pretool) use reach::sensitive_reach_reason;

/// What a pass over `grep` arguments read besides its verdict.
#[derive(Default)]
struct Scan {
    /// The patterns named by the command, as the shell passed them.
    patterns: Vec<String>,
    /// A pattern given in a form the scan cannot read back (`-efoo`, `-f`).
    pattern_unread: bool,
    /// `-v`, `-L` or `-c`: the output covers what does not match, or names
    /// and counts every file read, matching or not.
    reports_unmatched: bool,
    /// The search operands, after the pattern.
    targets: Vec<String>,
    recursive: bool,
    /// `--include` appears, so exact exclusions are not part of the proof.
    includes_present: bool,
    /// Exact names the command leaves out of its walk.
    excluded_files: Vec<String>,
    excluded_directories: Vec<String>,
}

impl Scan {
    /// The pattern, when it is the only one and the command prints the lines
    /// that match it: files it cannot match add nothing to the output.
    fn clearance(&self) -> Option<PatternClearance> {
        match self.patterns.as_slice() {
            [only] if !self.reports_unmatched && !self.pattern_unread => {
                PatternClearance::new(only)
            }
            _ => None,
        }
    }
}

/// One pass over `grep` arguments. With `pattern_from_option`, every
/// positional is a path, as it is when `-e` or `-f` appears anywhere.
fn arguments_pass(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    absent: AbsentOperands,
    pattern_from_option: bool,
) -> bool {
    scan_arguments(arguments, context, stdin_only, absent, pattern_from_option).0
}

/// [`arguments_pass`] with what it read.
fn scan_arguments(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    absent: AbsentOperands,
    pattern_from_option: bool,
) -> (bool, Scan) {
    let mut scan = Scan::default();
    let proven = scan_into(
        arguments,
        context,
        stdin_only,
        absent,
        pattern_from_option,
        &mut scan,
    );
    (proven, scan)
}

fn scan_into(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    absent: AbsentOperands,
    pattern_from_option: bool,
    scan: &mut Scan,
) -> bool {
    let mut pending_value: Option<SearchValueRole> = None;
    let mut pattern_supplied = pattern_from_option;
    let mut pattern_option_seen = false;
    let mut options_enabled = true;
    let mut recursive = false;
    let mut dereference = false;
    let mut targets = Vec::new();
    let mut excluded_files = Vec::new();
    let mut excluded_directories = Vec::new();
    let mut pending_exclusion = None;
    let mut includes_present = false;
    let mut positional_started = false;
    for argument in arguments {
        if let Some(directory) = pending_exclusion.take() {
            if argument.is_empty() {
                return false;
            }
            if exact_exclusion(argument) {
                if directory {
                    excluded_directories.push(argument.as_str());
                } else {
                    excluded_files.push(argument.as_str());
                }
            }
            continue;
        }
        if let Some(role) = pending_value.take() {
            if matches!(role, SearchValueRole::DirectoryAction)
                && argument.eq_ignore_ascii_case("recurse")
            {
                recursive = true;
                continue;
            }
            if unsafe_search_value(role, argument, context) {
                return false;
            }
            // `-f FILE` supplies the patterns as `-e` does.
            if matches!(role, SearchValueRole::Pattern | SearchValueRole::Path) {
                pattern_supplied = true;
                pattern_option_seen = true;
                if matches!(role, SearchValueRole::Pattern) {
                    scan.patterns.push(argument.clone());
                } else {
                    scan.pattern_unread = true;
                }
            }
            continue;
        }
        if options_enabled && argument == "--" {
            options_enabled = false;
            continue;
        }
        if options_enabled && argument.starts_with("--") {
            let (name, attached) = argument.split_once('=').unwrap_or((argument.as_str(), ""));
            if matches!(name, "--exclude" | "--exclude-dir") {
                if positional_started {
                    return false;
                }
                let directory = name == "--exclude-dir";
                if attached.is_empty() {
                    if argument.contains('=') {
                        return false;
                    }
                    pending_exclusion = Some(directory);
                } else if exact_exclusion(attached) {
                    if directory {
                        excluded_directories.push(attached);
                    } else {
                        excluded_files.push(attached);
                    }
                }
                continue;
            }
            includes_present |= name == "--include";
            scan.reports_unmatched |=
                matches!(name, "--invert-match" | "--files-without-match" | "--count");
            if matches!(name, "--recursive" | "--dereference-recursive") {
                if !attached.is_empty() {
                    return false;
                }
                recursive = true;
                dereference |= name == "--dereference-recursive";
                continue;
            }
            if matches!(name, "--file" | "--exclude-from") {
                return false;
            }
            let role = options::grep_value_role(name);
            if role.is_none() && !options::safe_grep_flag(name) {
                return false;
            }
            if let Some(role) = role {
                if stdin_only && matches!(role, SearchValueRole::Path) {
                    return false;
                }
                if matches!(role, SearchValueRole::DirectoryAction)
                    && attached.eq_ignore_ascii_case("recurse")
                {
                    recursive = true;
                    continue;
                }
                if attached.is_empty() {
                    pending_value = Some(role);
                } else if unsafe_search_value(role, attached, context) {
                    return false;
                } else if matches!(role, SearchValueRole::Pattern) {
                    pattern_supplied = true;
                    pattern_option_seen = true;
                    scan.patterns.push(attached.to_owned());
                }
            }
            continue;
        }
        if options_enabled && argument.starts_with('-') && argument.len() > 1 {
            if stdin_only
                && argument[1..]
                    .chars()
                    .take_while(|option| !matches!(option, 'e' | 'd' | 'A' | 'B' | 'C' | 'm'))
                    .any(|option| option == 'f')
            {
                return false;
            }
            // `-R` reads through every link it meets; `-r` follows one only
            // when it is named as an operand. The proof differs, so the two
            // are counted apart. BSD grep spells the same reach-through as
            // `-S` beside a recursive flag, and `-O` for an operand that is
            // itself a link, so both count as reading through as well.
            let bundled = || {
                argument[1..]
                    .chars()
                    .take_while(|option| !matches!(option, 'e' | 'f' | 'd' | 'A' | 'B' | 'C' | 'm'))
            };
            recursive |= bundled().any(|option| matches!(option, 'r' | 'R'));
            dereference |= bundled().any(|option| matches!(option, 'R' | 'S' | 'O'));
            scan.reports_unmatched |= bundled().any(|option| matches!(option, 'v' | 'L' | 'c'));
            let parsed = short_search_option(
                argument,
                &[],
                &[
                    ('e', SearchValueRole::Pattern),
                    ('f', SearchValueRole::Path),
                    ('d', SearchValueRole::DirectoryAction),
                    ('A', SearchValueRole::Other),
                    ('B', SearchValueRole::Other),
                    ('C', SearchValueRole::Other),
                    ('m', SearchValueRole::Other),
                ],
                context,
            );
            let Ok((next_value, supplied_pattern)) = parsed else {
                return false;
            };
            // `-efoo` and `-ffile` carry their value in the same word.
            scan.pattern_unread |= supplied_pattern && next_value.is_none();
            pending_value = next_value;
            pattern_supplied |= supplied_pattern;
            pattern_option_seen |= supplied_pattern;
            continue;
        }
        if pattern_supplied {
            if stdin_only {
                return false;
            }
            targets.push(argument.as_str());
            scan.targets.push(argument.clone());
            let proven = recursive
                || proven_glob(argument, context)
                || sibling::named_path(argument, context, absent.plain)
                || (absent.plain && absent_target(argument, context));
            if !proven && unsafe_search_value(SearchValueRole::Path, argument, context) {
                return false;
            }
        } else {
            // The first positional is the pattern, and it meets the same
            // screen a `-e` pattern does: a word the shell can still expand
            // into a credential operand is not matching text yet.
            if unsafe_search_value(SearchValueRole::Pattern, argument, context) {
                return false;
            }
            pattern_supplied = true;
            scan.patterns.push(argument.clone());
        }
        positional_started = true;
    }
    // GNU and BSD grep take the first positional as the pattern only when no
    // `-e` or `-f` supplies one, wherever that option appears: in
    // `grep .env -e KEY`, `.env` is a file. Check again with every
    // positional as a path.
    if pattern_option_seen && !pattern_from_option {
        *scan = Scan::default();
        return scan_into(arguments, context, stdin_only, absent, true, scan);
    }
    scan.recursive = recursive;
    scan.includes_present = includes_present;
    scan.excluded_files = excluded_files
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    scan.excluded_directories = excluded_directories
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let clearance = scan.clearance();
    pending_value.is_none()
        && pending_exclusion.is_none()
        // Include/exclude precedence differs across grep implementations. Do not
        // use exclusions as proof when an include could re-enable a file.
        && (!includes_present || (excluded_files.is_empty() && excluded_directories.is_empty()))
        && (!stdin_only || (pattern_supplied && !recursive))
        && (!recursive || {
            let proven = |target: &str| {
                tree::safe_recursive_target_excluding(
                    target,
                    context,
                    &excluded_files,
                    &excluded_directories,
                    true,
                    dereference,
                ) || (!dereference
                    && (sibling::grep_walk_root(
                        target,
                        context,
                        &excluded_files,
                        &excluded_directories,
                        true,
                    ) || proven_glob(target, context)))
                    // A sensitive file the pattern cannot match prints nothing.
                    || clearance.as_ref().is_some_and(|clearance| {
                        tree::safe_recursive_target_cleared(
                            target,
                            context,
                            &excluded_files,
                            &excluded_directories,
                            dereference,
                            clearance,
                        )
                    })
            };
            recursive_targets_proven(&targets, proven, absent.recursive.then_some(context))
        })
}

/// Every recursive root is proven, or missing beside at least one proven
/// root (`grep -rn x src tests` with no `tests`): a search whose only roots
/// are missing (`grep -rn x src/missing.ts`) proves nothing it reads.
fn recursive_targets_proven(
    targets: &[&str],
    proven: impl Fn(&str) -> bool,
    absent: Option<ReadContext<'_>>,
) -> bool {
    let mut real = false;
    targets.iter().copied().all(|target| {
        if proven(target) {
            real = true;
            return true;
        }
        absent.is_some_and(|context| absent_target(target, context))
    }) && real
}

/// A missing operand only prints an error, as a probe `ls` of the same path
/// does: its nearest existing ancestor must be a readable directory and every
/// missing name visible and clear of the sensitive screens. Agents pass a
/// fixed list of roots (`src tests lib`) whether or not each one exists.
fn absent_target(value: &str, context: ReadContext<'_>) -> bool {
    crate::pretool::listing_reads::absent_listing_operand(value, context)
}

/// A shell glob operand whose every expansion is screened, and whose matched
/// directories are walked like a recursive search root. This is how a glob
/// into a sibling repository, such as `~/code/api/src/*.ts`, is proven.
fn proven_glob(value: &str, context: ReadContext<'_>) -> bool {
    value.contains(['*', '?', '[']) && tree::safe_glob_search_operand(value, context)
}

fn exact_exclusion(value: &str) -> bool {
    !value.is_empty()
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
#[path = "grep_tests.rs"]
mod tests;
