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

/// The operand proof alone, as if `grep` were the whole command. Every caller
/// outside this module reads a segment, so the bare form is a test vantage.
#[cfg(test)]
pub(super) fn safe_grep_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    let absent = AbsentOperands {
        plain: true,
        recursive: true,
    };
    arguments_pass(arguments, context, false, absent, false)
}

/// A `grep` segment inside its command. A missing operand is proven only
/// while it stays missing: no other segment may create a file, directory or
/// link there (`ln -s <dir> <repo>/cfg && grep -rn . <repo>/cfg/` reads through
/// the fresh link). A recursive search walks whatever appears at a missing
/// root, which is the same question, so both routes ask it the same way.
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
    // Both absent routes read an operand as the command spells it, so a
    // drive path whose backslashes the shell drops before `grep` runs names
    // a different directory to the program than to the proof.
    let quoted = crate::pretool::directory_targets::drive_targets_quoted(segment);
    let unplanted = quoted && others.iter().all(|other| creates_nothing(other));
    let absent = AbsentOperands {
        plain: unplanted,
        recursive: unplanted,
    };
    let words = crate::pretool::listing_reads::literal_words(&segment.text);
    let context = ReadContext {
        literal_words: &words,
        ..context
    };
    arguments_pass(&segment.arguments, context, false, absent, false)
}

/// `literal_words` are the segment's quoted words, as
/// `listing_reads::literal_words` reads them.
pub(super) fn safe_stdin_arguments(arguments: &[String], literal_words: &[String]) -> bool {
    let absent = AbsentOperands {
        plain: false,
        recursive: false,
    };
    let context = crate::pretool::PathContext {
        literal_words,
        ..Default::default()
    };
    arguments_pass(arguments, context, true, absent, false)
}

pub(in crate::pretool) use writes_nothing::creates_nothing;

mod exclusion;
mod includes;
mod missing;
pub(super) use missing::unmatched_glob;
mod reach;
mod writes_nothing;
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
    /// `--include` appears beside an `--exclude` of any shape, which keeps
    /// the review however the walk is narrowed. An `--exclude-dir` beside an
    /// include stays part of the proof.
    include_beside_exclusion: bool,
    /// The `--include` globs: the only names the walk opens when present.
    included: Vec<String>,
    /// Exact names the command leaves out of its walk.
    excluded_files: Vec<String>,
    excluded_directories: Vec<String>,
}

impl Scan {
    /// The patterns, when the command prints the lines that match any of
    /// them: files none of them can match add nothing to the output.
    fn clearance(&self) -> Option<PatternClearance> {
        if self.reports_unmatched || self.pattern_unread {
            return None;
        }
        PatternClearance::any(&self.patterns)
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
    let mut exclusions = exclusion::Exclusions::default();
    let mut includes_present = false;
    let mut includes = includes::Includes::default();
    let mut positional_started = false;
    // Glob operands only the pattern clearance can prove, which is known
    // once every pattern is read.
    let mut cleared_globs: Vec<&str> = Vec::new();
    for argument in arguments {
        if let Some(proven) = exclusions.take_value(argument) {
            if !proven {
                return false;
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
            if includes.held(role, argument, context) {
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
            if let Some(proven) =
                exclusions.option(argument, positional_started, context, absent.plain)
            {
                if !proven {
                    return false;
                }
                continue;
            }
            let (name, attached) = argument.split_once('=').unwrap_or((argument.as_str(), ""));
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
                } else if !includes.held(role, attached, context) {
                    if unsafe_search_value(role, attached, context) {
                        return false;
                    }
                    if matches!(role, SearchValueRole::Pattern) {
                        pattern_supplied = true;
                        pattern_option_seen = true;
                        scan.patterns.push(attached.to_owned());
                    }
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
                // Without `-r` grep opens each match once, as `cat` would.
                || ((!argument.starts_with('~') || context.shell_home_matches)
                    && crate::pretool::safe_reads::glob_file_matches(argument, context).is_some())
                || sibling::named_path(argument, context, absent.plain)
                || (absent.plain && missing::missing_operand(argument, context));
            if !proven && unsafe_search_value(SearchValueRole::Path, argument, context) {
                if !argument.contains(['*', '?', '[']) {
                    return false;
                }
                cleared_globs.push(argument.as_str());
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
    scan.included = includes.globs().to_vec();
    scan.include_beside_exclusion = includes_present && !exclusions.leave_includes_exact();
    scan.excluded_files = exclusions
        .files
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    scan.excluded_directories = exclusions
        .directories
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let clearance = scan.clearance();
    let cleared_glob = |target: &str| {
        clearance
            .as_ref()
            .is_some_and(|clearance| tree::safe_glob_search_cleared(target, context, clearance))
    };
    pending_value.is_none()
        && !exclusions.pending()
        // Include/exclude precedence differs across grep implementations. Do not
        // use file exclusions as proof when an include could re-enable a file.
        // GNU grep also widens an include list whose first entry is an
        // exclude, so any `--exclude` beside an include keeps review too.
        // `--exclude-dir` is matched against directories only, so it holds.
        && (!includes_present || exclusions.leave_includes_exact())
        && includes.scope_proven(&targets, context)
        && (!stdin_only || (pattern_supplied && !recursive))
        && cleared_globs.iter().all(|glob| cleared_glob(glob))
        && (!recursive || {
            let proven = |target: &str| {
                tree::safe_recursive_target_excluding(
                    target,
                    context,
                    &exclusions.files,
                    &exclusions.directories,
                    true,
                    dereference,
                ) || (!dereference
                    && (sibling::grep_walk_root(
                        target,
                        context,
                        &exclusions.files,
                        &exclusions.directories,
                        true,
                        clearance.as_ref(),
                    ) || proven_glob(target, context)))
                    // `app/[slug]/route.ts` names one route when its class
                    // matches nothing, and is walked as that path.
                    || (!dereference && tree::safe_literal_bracket_search_target(target, context))
                    // A file operand starts no walk: `-r` opens it once.
                    || recursive_file_operand(target, context)
                    // A sensitive file the pattern cannot match prints nothing.
                    || clearance.as_ref().is_some_and(|clearance| {
                        tree::safe_recursive_target_cleared(
                            target,
                            context,
                            &exclusions.files,
                            &exclusions.directories,
                            dereference,
                            clearance,
                        ) || (!dereference
                            && sibling::grep_walk_root(
                                target,
                                context,
                                &exclusions.files,
                                &exclusions.directories,
                                true,
                                Some(clearance),
                            ))
                    })
                    // A glob reads a subset of the directory it expands below.
                    || (!dereference && cleared_glob(target))
                    // An include opens only the files its globs select. This
                    // walks the tree again, so it is asked last: every reading
                    // above answers the same question without it.
                    || (!dereference && includes.narrows(target, context))
                    // A skill tree opens only documents and scripts a direct
                    // read allows. That walk refuses every link it meets.
                    || includes.skill_tree(target, context)
            };
            missing::recursive_targets_proven(&targets, proven, context, absent.recursive)
        })
}

/// A missing operand only prints an error, as a probe `ls` of the same path
/// does: its nearest existing ancestor must be a readable directory and every
/// missing name visible and clear of the sensitive screens. Agents pass a
/// fixed list of roots (`src tests lib`) whether or not each one exists.
///
/// The shell expands `~` from its own `HOME` while this screen reads the
/// declared one, so a `~` root is proven absent only once `shell_home_matches`
/// says the two name one directory. Without that, the search could open a tree
/// that is there under the shell's home while the proof measured a name that
/// is not there under the declared one. The recursive listing screen agrees.
pub(super) fn absent_target(value: &str, context: ReadContext<'_>) -> bool {
    (!value.starts_with('~') || context.shell_home_matches)
        && crate::pretool::listing_reads::absent_listing_operand(value, context)
}

/// `grep -r` walks only a directory operand. A regular file named as an
/// operand, or a link to one, is opened once exactly as plain `grep` opens it,
/// so it takes the plain read screen rather than the walk proof. The walk
/// proof refuses any `..` because a walk above the working directory reaches
/// a tree whose ignore rules were never read; one file reaches no tree.
fn recursive_file_operand(value: &str, context: ReadContext<'_>) -> bool {
    !value.contains(['*', '?', '['])
        && (!value.starts_with('~') || context.shell_home_matches)
        && tree::expanded_operand(value, context)
            .is_some_and(|path| std::fs::metadata(path).is_ok_and(|meta| meta.is_file()))
        && !unsafe_search_value(SearchValueRole::Path, value, context)
}

/// A shell glob operand whose every expansion is screened, and whose matched
/// directories are walked like a recursive search root. This is how a glob
/// into a sibling repository, such as `~/code/api/src/*.ts`, is proven. A
/// match whose word starts with `-`, as `*/*.py` gives for `-ve/a.py`, would
/// reach grep as an option instead.
fn proven_glob(value: &str, context: ReadContext<'_>) -> bool {
    value.contains(['*', '?', '['])
        && !tree::glob_may_name_an_option(value, context)
        && tree::safe_glob_search_operand(value, context)
}

#[cfg(test)]
#[path = "grep_include_tests.rs"]
mod include_tests;
#[cfg(test)]
#[path = "grep_parent_root_tests.rs"]
mod parent_root_tests;
#[cfg(test)]
#[path = "grep_tests.rs"]
mod tests;
