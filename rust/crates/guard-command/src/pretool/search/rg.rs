//! Proof for `rg` arguments: every path it may read, the ignore files that
//! could re-include hidden ones, and the options that change either.

use super::{
    options, rg_whitelist, short_search_option, sibling, tree, unsafe_search_value, ReadContext,
    SearchValueRole,
};

pub(in crate::pretool) fn safe_rg_stdin_arguments(arguments: &[String]) -> bool {
    safe_rg_arguments_inner(
        arguments,
        crate::pretool::PathContext::default(),
        true,
        true,
        true,
    )
}

pub(super) fn safe_rg_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    safe_rg_arguments_inner(arguments, context, false, true, true)
}

/// An `rg` segment inside its command. A missing operand is proven only
/// while it stays missing: no other segment may create a file, directory or
/// link there, because `rg` reads whatever appears at that path and walks it
/// when it turns out to be a directory.
pub(super) fn safe_rg_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: ReadContext<'_>,
) -> bool {
    // Downstream of a pipe and with no path operand, `rg` reads the previous
    // step's output: it opens no file and walks no directory, so the ignore
    // files below the working directory have nothing to re-include and the
    // root proof has no root to answer for. Without this, every
    // `git diff | rg PATTERN` in a repository whose `.gitignore` carries a
    // `!.env.example` rule went to review for a search that never touches
    // the tree.
    if segment.pipeline_index > 0
        && config_cannot_add_arguments(&segment.arguments, context)
        && safe_rg_stdin_arguments(&segment.arguments)
    {
        return true;
    }
    let absent = model
        .segments
        .iter()
        .filter(|other| other.span != segment.span)
        .all(|other| super::grep::creates_nothing(other, true));
    safe_rg_arguments_inner(&segment.arguments, context, false, true, absent)
}

/// A review reason for a lone `rg` held back only because an ignore file
/// under its roots re-includes a hidden file it would then read. Told just
/// that the command "could not be confirmed read-only", agents split it
/// further; naming the directories to search is what Guard can prove.
/// `None` for every other command.
pub(in crate::pretool) fn rg_hidden_whitelist_reason(
    model: &crate::CanonicalCommandV1,
    context: ReadContext<'_>,
) -> Option<String> {
    let [segment] = model.segments.as_slice() else {
        return None;
    };
    let held = model.confidence == "exact"
        && !model.path_overridden
        && model.wrapper_chain.is_empty()
        && segment.environment_names.is_empty()
        && super::super::executable_basename(segment.executable.as_deref()?) == "rg"
        && safe_rg_arguments_inner(&segment.arguments, context, false, false, true)
        && !safe_rg_arguments_inner(&segment.arguments, context, false, true, true);
    held.then(|| {
        "HOL Guard requires review because an ignore file here re-includes a hidden file (for example a `!.env.example` rule), so rg would read that file too. Name the directories to search, such as `rg PATTERN src docs`, or list names with `rg --files`."
            .to_owned()
    })
}

/// Whether no inherited `RIPGREP_CONFIG_PATH` can add arguments to this
/// `rg`.
///
/// A config file's lines become command-line arguments, so one can hand the
/// command a path of its own. A filter that only reads its input would then
/// search that file instead, which is why a piped `rg` still has to answer
/// for the config even though it walks no tree itself.
fn config_cannot_add_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    context.ripgrep_config_absent || config_option_present(arguments)
}

/// Short options that take the next argument as their value, as the parsed
/// pass below reads them.
const RG_SHORT_VALUE_OPTIONS: [char; 13] = [
    'e', 'f', 'g', 'A', 'B', 'C', 'E', 'j', 'm', 'M', 'r', 't', 'T',
];

/// Whether `--no-config` is here as an option rather than as the value of
/// one.
///
/// `rg -e --no-config` searches its input for that string, and
/// `rg --replace --no-config` writes it over every match: an option takes
/// the next argument whatever it looks like. Reading either as the flag
/// would clear a config the command still loads, and the config's lines
/// become arguments of their own, so option values are stepped over here the
/// way the parsed pass steps over them, and `--` ends the options.
fn config_option_present(arguments: &[String]) -> bool {
    let mut pending_value = false;
    for argument in arguments {
        if std::mem::take(&mut pending_value) {
            continue;
        }
        if argument == "--" {
            return false;
        }
        if let Some(name) = argument.strip_prefix("--").filter(|name| !name.is_empty()) {
            match name.split_once('=') {
                // `--opt=value` carries its value, so the next argument is an
                // option or an operand again.
                Some((name, _)) => {
                    if name == "no-config" {
                        return true;
                    }
                }
                None => {
                    if name == "no-config" {
                        return true;
                    }
                    pending_value = options::rg_value_role(argument).is_some();
                }
            }
            continue;
        }
        if let Some(cluster) = argument.strip_prefix('-').filter(|rest| !rest.is_empty()) {
            // The first value-taking letter consumes the rest of the cluster,
            // and the next argument only when nothing is attached to it.
            if let Some((offset, option)) = cluster
                .char_indices()
                .find(|(_, option)| RG_SHORT_VALUE_OPTIONS.contains(option))
            {
                pending_value = cluster[offset + option.len_utf8()..].is_empty();
            }
        }
    }
    false
}

fn safe_rg_arguments_inner(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    prove_roots: bool,
    allow_absent: bool,
) -> bool {
    rg_arguments_pass(
        arguments,
        context,
        stdin_only,
        prove_roots,
        false,
        allow_absent,
    )
}

/// One pass over `rg` arguments. With `pattern_from_option`, every
/// positional is a path, as it is when `-e` or `-f` appears anywhere.
fn rg_arguments_pass(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    prove_roots: bool,
    pattern_from_option: bool,
    allow_absent: bool,
) -> bool {
    let mut pending_value: Option<SearchValueRole> = None;
    // `-g`/`--glob` (not the case-blind `--iglob`) awaiting its value.
    let mut pending_glob = false;
    // Inclusion globs the name screen cannot clear, such as `*.md`; proven
    // below by what they select on disk.
    let mut unscreened_globs: Vec<&str> = Vec::new();
    let mut pattern_supplied = pattern_from_option;
    let mut pattern_option_seen = false;
    let mut options_enabled = true;
    let mut paths_only = false;
    let mut config_disabled = false;
    let mut roots: Vec<&str> = Vec::new();
    for argument in arguments {
        if let Some(role) = pending_value.take() {
            if unsafe_search_value(role, argument, context) {
                if !std::mem::take(&mut pending_glob) || stdin_only {
                    return false;
                }
                unscreened_globs.push(argument);
                continue;
            }
            pending_glob = false;
            // `--file` is the only path-valued option and supplies patterns.
            if matches!(role, SearchValueRole::Pattern | SearchValueRole::Path) {
                pattern_supplied = true;
                pattern_option_seen = true;
            }
            continue;
        }
        if options_enabled && argument == "--" {
            options_enabled = false;
            continue;
        }
        if options_enabled && argument.starts_with("--") {
            let (name, attached) = argument.split_once('=').unwrap_or((argument.as_str(), ""));
            if matches!(
                name,
                "--hidden"
                    | "--unrestricted"
                    | "--no-ignore"
                    | "--no-ignore-vcs"
                    | "--no-ignore-global"
                    | "--no-ignore-parent"
                    | "--no-ignore-dot"
                    | "--no-ignore-exclude"
                    | "--no-ignore-files"
                    | "--follow"
                    | "--pre"
                    | "--pre-glob"
                    | "--hostname-bin"
            ) {
                return false;
            }
            let role = options::rg_value_role(name);
            config_disabled |= name == "--no-config";
            if name == "--files" {
                if stdin_only {
                    return false;
                }
                paths_only = true;
            }
            if role.is_none() && !options::safe_rg_flag(name) {
                return false;
            }
            if let Some(role) = role {
                if stdin_only && matches!(role, SearchValueRole::Path) {
                    return false;
                }
                let glob = name == "--glob";
                if attached.is_empty() {
                    pending_value = Some(role);
                    pending_glob = glob;
                } else if unsafe_search_value(role, attached, context) {
                    if !glob || stdin_only {
                        return false;
                    }
                    unscreened_globs.push(attached);
                } else if matches!(role, SearchValueRole::Pattern | SearchValueRole::Path) {
                    pattern_supplied = true;
                    pattern_option_seen = true;
                }
            }
            continue;
        }
        if options_enabled && argument.starts_with('-') && argument.len() > 1 {
            if stdin_only
                && argument[1..]
                    .chars()
                    .take_while(|option| {
                        !matches!(
                            option,
                            'e' | 'g' | 'A' | 'B' | 'C' | 'E' | 'j' | 'm' | 'M' | 'r' | 't' | 'T'
                        )
                    })
                    .any(|option| option == 'f')
            {
                return false;
            }
            if let Some(glob) = argument.strip_prefix("-g").filter(|glob| !glob.is_empty()) {
                if unsafe_search_value(SearchValueRole::RgGlob, glob, context) {
                    if stdin_only {
                        return false;
                    }
                    unscreened_globs.push(glob);
                }
                continue;
            }
            let parsed = short_search_option(
                argument,
                &['u', '.', 'L'],
                &[
                    ('e', SearchValueRole::Pattern),
                    ('f', SearchValueRole::Path),
                    ('g', SearchValueRole::RgGlob),
                    ('A', SearchValueRole::Other),
                    ('B', SearchValueRole::Other),
                    ('C', SearchValueRole::Other),
                    ('E', SearchValueRole::Other),
                    ('j', SearchValueRole::Other),
                    ('m', SearchValueRole::Other),
                    ('M', SearchValueRole::Other),
                    ('r', SearchValueRole::Other),
                    ('t', SearchValueRole::RgType),
                    ('T', SearchValueRole::Other),
                ],
                context,
            );
            let Ok((next_value, supplied_pattern)) = parsed else {
                return false;
            };
            pending_glob = matches!(next_value, Some(SearchValueRole::RgGlob));
            pending_value = next_value;
            pattern_supplied |= supplied_pattern;
            pattern_option_seen |= supplied_pattern;
            continue;
        }
        if paths_only || pattern_supplied {
            if stdin_only {
                return false;
            }
            // A broad search of only parent directories traverses unrelated
            // sibling projects. Named sibling paths still use canonical
            // provenance checks, but `rg pattern ../` remains at review.
            let directories: Vec<_> = argument
                .split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .collect();
            if !directories.is_empty() && directories.iter().all(|part| *part == "..") {
                return false;
            }
            roots.push(argument);
            // A shell glob that lexically could reach a hidden or credential
            // path is still proven when every expansion is an ordinary file,
            // or a directory below the cwd whose whole tree is ordinary.
            if unsafe_search_value(SearchValueRole::Path, argument, context)
                && !tree::rg_root_inside_cwd(argument, context)
                && !sibling::rg_sibling_repository_root(argument, context)
                && !sibling::named_path(argument, context, allow_absent)
                && !tree::safe_recursive_search_target(argument, context)
                && !tree::safe_literal_bracket_search_target(argument, context)
                && (!argument.contains(['*', '?', '['])
                    || !tree::safe_glob_search_operand(argument, context))
            {
                return false;
            }
        } else {
            pattern_supplied = true;
        }
    }
    // `rg` takes the first positional as the pattern only when no `-e` or
    // `-f` supplies one, wherever that option appears: in `rg .env -e KEY`,
    // `.env` is a path. Check again with every positional as a path.
    if pattern_option_seen && !pattern_from_option {
        return rg_arguments_pass(
            arguments,
            context,
            stdin_only,
            prove_roots,
            true,
            allow_absent,
        );
    }
    // An inherited RIPGREP_CONFIG_PATH prepends its lines to these
    // arguments, so `--pre`, `--hidden` or `--no-ignore` there would undo
    // every check above. A stdin filter walks no files, so the config's
    // file options have nothing to act on.
    let scope: &[&str] = if roots.is_empty() { &["."] } else { &roots };
    pending_value.is_none()
        && (!stdin_only || pattern_supplied)
        && (stdin_only || config_disabled || context.ripgrep_config_absent)
        && (stdin_only || paths_only || !prove_roots || rg_whitelist::roots_proven(&roots, context))
        && (unscreened_globs.is_empty()
            || super::super::search_scope::rg_glob_scope_proven(
                scope,
                &unscreened_globs,
                context.home_dir,
                context.cwd,
            ))
}

#[cfg(test)]
mod tests {
    use super::config_option_present;

    fn arguments(line: &str) -> Vec<String> {
        line.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn the_flag_counts_only_where_ripgrep_reads_it_as_an_option() {
        for line in [
            "--no-config PATTERN",
            "-n --no-config PATTERN",
            "--no-config -e PATTERN",
            "-e PATTERN --no-config",
            "-A3 --no-config PATTERN",
            "--max-count=2 --no-config PATTERN",
            "-in --no-config PATTERN",
        ] {
            assert!(config_option_present(&arguments(line)), "{line}");
        }
        for line in [
            "PATTERN",
            // The value of an option, whatever it is spelled like.
            "-e --no-config",
            "--max-count --no-config",
            "--replace --no-config",
            "-f --no-config",
            "-C --no-config -e PATTERN",
            "-ie --no-config",
            // Past `--` every argument is an operand.
            "-- --no-config",
            "PATTERN -- --no-config",
        ] {
            assert!(!config_option_present(&arguments(line)), "{line}");
        }
    }
}
