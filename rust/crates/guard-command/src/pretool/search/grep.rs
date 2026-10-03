use super::{
    options, short_search_option, tree, unsafe_search_value, ReadContext, SearchValueRole,
};

pub(super) fn safe_grep_arguments(arguments: &[String], context: ReadContext<'_>) -> bool {
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
        && (!recursive
            || (!targets.is_empty()
                && targets
                    .iter()
                    .all(|target| tree::safe_recursive_target(target, context))))
}
