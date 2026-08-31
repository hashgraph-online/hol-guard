use super::sensitive_path_argument;
use std::collections::{HashSet, VecDeque};
mod hint;
fn glob_matches(pattern: &[u8], value: &[u8]) -> bool {
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    let mut pattern_index = 0;
    while pattern_index < pattern.len() {
        let mut current = vec![false; value.len() + 1];
        if pattern[pattern_index] == b'*' {
            current[0] = previous[0];
            for value_index in 1..=value.len() {
                current[value_index] = previous[value_index] || current[value_index - 1];
            }
            pattern_index += 1;
        } else {
            let (token_end, matcher): (usize, Box<dyn Fn(u8) -> bool>) =
                if pattern[pattern_index] == b'[' {
                    if let Some(relative_end) = pattern[pattern_index..]
                        .iter()
                        .position(|character| *character == b']')
                    {
                        let class_end = pattern_index + relative_end;
                        let class = pattern[pattern_index + 1..class_end].to_vec();
                        (
                            class_end + 1,
                            Box::new(move |byte| glob_class_matches(&class, byte)),
                        )
                    } else {
                        (pattern_index + 1, Box::new(|byte| byte == b'['))
                    }
                } else if pattern[pattern_index] == b'?' {
                    (pattern_index + 1, Box::new(|_byte| true))
                } else if pattern[pattern_index] == b'\\' && pattern_index + 1 < pattern.len() {
                    let literal = pattern[pattern_index + 1];
                    (pattern_index + 2, Box::new(move |byte| byte == literal))
                } else {
                    let literal = pattern[pattern_index];
                    (pattern_index + 1, Box::new(move |byte| byte == literal))
                };
            for value_index in 1..=value.len() {
                current[value_index] = previous[value_index - 1] && matcher(value[value_index - 1]);
            }
            pattern_index = token_end;
        }
        previous = current;
    }
    previous[value.len()]
}
fn glob_class_matches(class: &[u8], value: u8) -> bool {
    let (negated, members) = match class.first() {
        Some(b'!' | b'^') => (true, &class[1..]),
        _ => (false, class),
    };
    let mut matched = false;
    let mut index = 0;
    while index < members.len() {
        if index + 2 < members.len() && members[index + 1] == b'-' {
            matched |= members[index] <= value && value <= members[index + 2];
            index += 3;
        } else {
            matched |= members[index] == value;
            index += 1;
        }
    }
    matched != negated
}
fn glob_token_matches(pattern: &[u8], index: usize, value: u8) -> (usize, bool) {
    if pattern[index] == b'[' {
        if let Some(relative_end) = pattern[index..]
            .iter()
            .position(|character| *character == b']')
        {
            let class_end = index + relative_end;
            return (
                class_end + 1,
                glob_class_matches(&pattern[index + 1..class_end], value),
            );
        }
    }
    if pattern[index] == b'\\' && index + 1 < pattern.len() {
        return (index + 2, pattern[index + 1] == value);
    }
    (index + 1, pattern[index] == b'?' || pattern[index] == value)
}
fn glob_intersects_dfa<Accept, Transition>(
    pattern: &[u8],
    initial_state: usize,
    star_consumes: bool,
    accepts: Accept,
    transition: Transition,
) -> bool
where
    Accept: Fn(usize) -> bool,
    Transition: Fn(usize, u8) -> Option<usize>,
{
    let mut pending = VecDeque::from([(0_usize, initial_state)]);
    let mut visited = HashSet::new();
    while let Some((pattern_index, family_state)) = pending.pop_front() {
        if !visited.insert((pattern_index, family_state)) {
            continue;
        }
        if pattern_index == pattern.len() {
            if accepts(family_state) {
                return true;
            }
            continue;
        }
        if pattern[pattern_index] == b'*' {
            pending.push_back((pattern_index + 1, family_state));
            if star_consumes {
                for value in 32_u8..=126 {
                    if let Some(next_family) = transition(family_state, value) {
                        pending.push_back((pattern_index, next_family));
                    }
                }
            }
            continue;
        }
        for value in 32_u8..=126 {
            let (next_pattern, matches) = glob_token_matches(pattern, pattern_index, value);
            if matches {
                if let Some(next_family) = transition(family_state, value) {
                    pending.push_back((next_pattern, next_family));
                }
            }
        }
    }
    false
}
fn glob_intersects_prefix_family(pattern: &[u8], prefix: &[u8]) -> bool {
    glob_intersects_dfa(
        pattern,
        0,
        true,
        |state| state == prefix.len(),
        |state, value| {
            if state == prefix.len() {
                Some(state)
            } else if prefix[state] == value {
                Some(state + 1)
            } else {
                None
            }
        },
    )
}
fn contains_family_transition(needle: &[u8], state: usize, value: u8) -> usize {
    if state == needle.len() {
        return state;
    }
    let total_len = state + 1;
    for candidate_len in (0..=needle.len().min(total_len)).rev() {
        let matches = (0..candidate_len).all(|offset| {
            let source_index = total_len - candidate_len + offset;
            let source = if source_index < state {
                needle[source_index]
            } else {
                value
            };
            source == needle[offset]
        });
        if matches {
            return candidate_len;
        }
    }
    0
}
fn glob_intersects_contains_family(pattern: &[u8], needle: &[u8], star_consumes: bool) -> bool {
    glob_intersects_dfa(
        pattern,
        0,
        star_consumes,
        |state| state == needle.len(),
        |state, value| Some(contains_family_transition(needle, state, value)),
    )
}
fn expand_brace_globs(pattern: &str) -> Option<Vec<String>> {
    let mut expanded = vec![pattern.to_owned()];
    for _depth in 0..8 {
        let Some(index) = expanded
            .iter()
            .position(|candidate| candidate.contains('{'))
        else {
            return Some(expanded);
        };
        let candidate = expanded.swap_remove(index);
        let open = candidate.find('{')?;
        let close = candidate[open + 1..].find('}')? + open + 1;
        let choices: Vec<&str> = candidate[open + 1..close].split(',').collect();
        if choices.len() < 2 || expanded.len() + choices.len() > 16 {
            return None;
        }
        for choice in choices {
            expanded.push(format!(
                "{}{}{}",
                &candidate[..open],
                choice,
                &candidate[close + 1..]
            ));
        }
    }
    None
}
fn glob_can_select_sensitive_path(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    if normalized.len() > 512
        || normalized
            .bytes()
            .filter(|character| matches!(character, b'*' | b'?' | b'[' | b'{' | b'}'))
            .count()
            > 64
    {
        return true;
    }
    if !normalized
        .bytes()
        .any(|character| matches!(character, b'*' | b'?' | b'[' | b'{'))
    {
        return false;
    }
    let Some(patterns) = expand_brace_globs(&normalized) else {
        return true;
    };
    let sensitive_components = [
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".git-credentials",
        ".git",
        ".aws",
        ".docker",
        ".kube",
        ".gnupg",
        ".ssh",
        "terraform.tfvars",
        "private-key.pem",
        "private.key",
        "wallet.key",
    ];
    patterns.iter().any(|pattern| {
        pattern.split('/').any(|component| {
            let bytes = component.as_bytes();
            let env_hint = hint::glob_constrained_lcs(bytes, b".env.") >= 2;
            let family_hint = [
                b"private-key".as_slice(),
                b"private_key",
                b"wallet-key",
                b"wallet_key",
            ]
            .iter()
            .any(|family| hint::glob_constrained_lcs(bytes, family) >= 3);
            sensitive_components
                .iter()
                .any(|candidate| glob_matches(bytes, candidate.as_bytes()))
                || (env_hint && glob_intersects_prefix_family(bytes, b".env."))
                || (family_hint
                    && [
                        b"private-key".as_slice(),
                        b"private_key",
                        b"wallet-key",
                        b"wallet_key",
                    ]
                    .iter()
                    .any(|needle| glob_intersects_contains_family(bytes, needle, true)))
        })
    })
}
#[derive(Clone, Copy)]
enum SearchValueRole {
    Pattern,
    Glob,
    Path,
    TypeGlob,
    DirectoryAction,
    Other,
}
fn unsafe_search_value(role: SearchValueRole, value: &str) -> bool {
    match role {
        SearchValueRole::Glob | SearchValueRole::Path => {
            sensitive_path_argument(value) || glob_can_select_sensitive_path(value)
        }
        SearchValueRole::TypeGlob => value.split_once(':').map_or(true, |(_, glob)| {
            sensitive_path_argument(glob) || glob_can_select_sensitive_path(glob)
        }),
        SearchValueRole::DirectoryAction => value.eq_ignore_ascii_case("recurse"),
        SearchValueRole::Pattern | SearchValueRole::Other => false,
    }
}
fn short_search_option(
    argument: &str,
    dangerous: &[char],
    value_options: &[(char, SearchValueRole)],
) -> Result<(Option<SearchValueRole>, bool), ()> {
    for (offset, option) in argument[1..].char_indices() {
        if dangerous.contains(&option) {
            return Err(());
        }
        if let Some((_, role)) = value_options.iter().find(|(name, _)| *name == option) {
            let value_start = offset + option.len_utf8();
            let attached = &argument[1 + value_start..];
            if !attached.is_empty() && unsafe_search_value(*role, attached) {
                return Err(());
            }
            return Ok((
                attached.is_empty().then_some(*role),
                matches!(role, SearchValueRole::Pattern),
            ));
        }
    }
    Ok((None, false))
}

pub(super) fn safe_search_arguments(executable: &str, arguments: &[String]) -> bool {
    match executable {
        "rg" => safe_rg_arguments(arguments),
        "grep" => safe_grep_arguments(arguments),
        _ => false,
    }
}

fn safe_rg_arguments(arguments: &[String]) -> bool {
    let mut pending_value: Option<SearchValueRole> = None;
    let mut pattern_supplied = false;
    let mut options_enabled = true;
    let mut paths_only = false;
    for argument in arguments {
        if let Some(role) = pending_value.take() {
            if unsafe_search_value(role, argument) {
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
            let role = match name {
                "--glob" | "--iglob" => Some(SearchValueRole::Glob),
                "--regexp" => Some(SearchValueRole::Pattern),
                "--file" | "--ignore-file" => Some(SearchValueRole::Path),
                "--type-add" => Some(SearchValueRole::TypeGlob),
                "--after-context" | "--before-context" | "--context" | "--encoding"
                | "--engine" | "--max-columns" | "--max-count" | "--max-depth" | "--threads"
                | "--type" | "--type-clear" | "--type-not" => Some(SearchValueRole::Other),
                _ => None,
            };
            if name == "--files" {
                paths_only = true;
            }
            if let Some(role) = role {
                if attached.is_empty() {
                    pending_value = Some(role);
                } else if unsafe_search_value(role, attached) {
                    return false;
                } else if matches!(role, SearchValueRole::Pattern) {
                    pattern_supplied = true;
                }
            }
            continue;
        }
        if options_enabled && argument.starts_with('-') && argument.len() > 1 {
            let parsed = short_search_option(
                argument,
                &['u', '.', 'L'],
                &[
                    ('e', SearchValueRole::Pattern),
                    ('f', SearchValueRole::Path),
                    ('g', SearchValueRole::Glob),
                    ('A', SearchValueRole::Other),
                    ('B', SearchValueRole::Other),
                    ('C', SearchValueRole::Other),
                    ('E', SearchValueRole::Other),
                    ('j', SearchValueRole::Other),
                    ('m', SearchValueRole::Other),
                    ('M', SearchValueRole::Other),
                    ('r', SearchValueRole::Other),
                    ('t', SearchValueRole::Other),
                    ('T', SearchValueRole::Other),
                ],
            );
            let Ok((next_value, supplied_pattern)) = parsed else {
                return false;
            };
            pending_value = next_value;
            pattern_supplied |= supplied_pattern;
            continue;
        }
        if paths_only || pattern_supplied {
            if sensitive_path_argument(argument) || glob_can_select_sensitive_path(argument) {
                return false;
            }
        } else {
            pattern_supplied = true;
        }
    }
    pending_value.is_none()
}

fn safe_grep_arguments(arguments: &[String]) -> bool {
    let mut pending_value: Option<SearchValueRole> = None;
    let mut pattern_supplied = false;
    let mut options_enabled = true;
    for argument in arguments {
        if let Some(role) = pending_value.take() {
            if unsafe_search_value(role, argument) {
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
            if matches!(
                name,
                "--recursive" | "--dereference-recursive" | "--file" | "--exclude-from"
            ) {
                return false;
            }
            let role = match name {
                "--regexp" => Some(SearchValueRole::Pattern),
                "--directories" => Some(SearchValueRole::DirectoryAction),
                "--after-context" | "--before-context" | "--context" | "--max-count" => {
                    Some(SearchValueRole::Other)
                }
                _ => None,
            };
            if let Some(role) = role {
                if attached.is_empty() {
                    pending_value = Some(role);
                } else if unsafe_search_value(role, attached) {
                    return false;
                } else if matches!(role, SearchValueRole::Pattern) {
                    pattern_supplied = true;
                }
            }
            continue;
        }
        if options_enabled && argument.starts_with('-') && argument.len() > 1 {
            let parsed = short_search_option(
                argument,
                &['r', 'R'],
                &[
                    ('e', SearchValueRole::Pattern),
                    ('f', SearchValueRole::Path),
                    ('d', SearchValueRole::DirectoryAction),
                    ('A', SearchValueRole::Other),
                    ('B', SearchValueRole::Other),
                    ('C', SearchValueRole::Other),
                    ('m', SearchValueRole::Other),
                ],
            );
            let Ok((next_value, supplied_pattern)) = parsed else {
                return false;
            };
            pending_value = next_value;
            pattern_supplied |= supplied_pattern;
            continue;
        }
        if pattern_supplied {
            if sensitive_path_argument(argument) || glob_can_select_sensitive_path(argument) {
                return false;
            }
        } else {
            pattern_supplied = true;
        }
    }
    pending_value.is_none()
}
