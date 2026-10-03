use super::{
    options, short_search_option, tree, unsafe_search_value, ReadContext, SearchValueRole,
};

pub(super) fn safe_grep_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
    safe_arguments(arguments, context, false)
}

pub(super) fn safe_stdin_arguments(arguments: &[String]) -> bool {
    safe_arguments(arguments, crate::pretool::PathContext::default(), true)
}

fn safe_arguments(arguments: &[String], context: ReadContext<'_>, stdin_only: bool) -> bool {
    let mut pending_value: Option<SearchValueRole> = None;
    let mut pattern_supplied = false;
    let mut options_enabled = true;
    let mut recursive = false;
    let mut targets = Vec::new();
    for argument in arguments {
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
            if matches!(role, SearchValueRole::Pattern) {
                pattern_supplied = true;
            }
            continue;
        }
        if options_enabled && argument == "--" {
            options_enabled = false;
            continue;
        }
        if options_enabled && argument.starts_with("--") {
            let (name, attached) = argument.split_once('=').unwrap_or((argument.as_str(), ""));
            if matches!(name, "--recursive" | "--dereference-recursive") {
                if !attached.is_empty() {
                    return false;
                }
                recursive = true;
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
            recursive |= argument[1..]
                .chars()
                .take_while(|option| !matches!(option, 'e' | 'f' | 'd' | 'A' | 'B' | 'C' | 'm'))
                .any(|option| matches!(option, 'r' | 'R'));
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
            pending_value = next_value;
            pattern_supplied |= supplied_pattern;
            continue;
        }
        if pattern_supplied {
            if stdin_only {
                return false;
            }
            targets.push(argument.as_str());
            if unsafe_search_value(SearchValueRole::Path, argument, context)
                && !(recursive && tree::safe_recursive_target(argument, context))
            {
                return false;
            }
        } else {
            pattern_supplied = true;
        }
    }
    pending_value.is_none()
        && (!stdin_only || (pattern_supplied && !recursive))
        && (!recursive
            || (!targets.is_empty()
                && targets
                    .iter()
                    .all(|target| tree::safe_recursive_target(target, context))))
}

#[cfg(test)]
mod tests {
    #[test]
    fn stdin_proof_cannot_open_files_or_recurse() {
        for (arguments, allowed) in [
            (vec!["-n", "-e", "fixture"], true),
            (vec!["-efixt"], true),
            (vec!["--regexp=fixture"], true),
            (vec!["-f", "one.txt"], false),
            (vec!["-nfone.txt"], false),
            (vec!["--file=one.txt"], false),
            (vec!["fixture", "one.txt"], false),
            (vec!["-r", "fixture"], false),
            (vec!["--directories=recurse", "fixture"], false),
            (vec!["-e", "fixture", "-f", "one.txt"], false),
            (vec!["--", "fixture", "one.txt"], false),
            (vec![], false),
        ] {
            let arguments: Vec<String> = arguments.into_iter().map(str::to_owned).collect();
            assert_eq!(
                super::safe_stdin_arguments(&arguments),
                allowed,
                "{arguments:?}"
            );
        }
    }
}
