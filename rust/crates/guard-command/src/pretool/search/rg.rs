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
    )
}

pub(super) fn safe_rg_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    safe_rg_arguments_inner(arguments, context, false, true)
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
        && safe_rg_arguments_inner(&segment.arguments, context, false, false)
        && !safe_rg_arguments_inner(&segment.arguments, context, false, true);
    held.then(|| {
        "HOL Guard requires review because an ignore file here re-includes a hidden file (for example a `!.env.example` rule), so rg would read that file too. Name the directories to search, such as `rg PATTERN src docs`, or list names with `rg --files`."
            .to_owned()
    })
}

fn safe_rg_arguments_inner(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    prove_roots: bool,
) -> bool {
    rg_arguments_pass(arguments, context, stdin_only, prove_roots, false)
}

/// One pass over `rg` arguments. With `pattern_from_option`, every
/// positional is a path, as it is when `-e` or `-f` appears anywhere.
fn rg_arguments_pass(
    arguments: &[String],
    context: ReadContext<'_>,
    stdin_only: bool,
    prove_roots: bool,
    pattern_from_option: bool,
) -> bool {
    let mut pending_value: Option<SearchValueRole> = None;
    let mut pattern_supplied = pattern_from_option;
    let mut pattern_option_seen = false;
    let mut options_enabled = true;
    let mut paths_only = false;
    let mut config_disabled = false;
    let mut roots: Vec<&str> = Vec::new();
    for argument in arguments {
        if let Some(role) = pending_value.take() {
            if unsafe_search_value(role, argument, context) {
                return false;
            }
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
                if attached.is_empty() {
                    pending_value = Some(role);
                } else if unsafe_search_value(role, attached, context) {
                    return false;
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
                && !tree::safe_recursive_search_target(argument, context)
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
        return rg_arguments_pass(arguments, context, stdin_only, prove_roots, true);
    }
    // An inherited RIPGREP_CONFIG_PATH prepends its lines to these
    // arguments, so `--pre`, `--hidden` or `--no-ignore` there would undo
    // every check above. A stdin filter walks no files, so the config's
    // file options have nothing to act on.
    pending_value.is_none()
        && (!stdin_only || pattern_supplied)
        && (stdin_only || config_disabled || context.ripgrep_config_absent)
        && (stdin_only || paths_only || !prove_roots || rg_whitelist::roots_proven(&roots, context))
}
