use super::sensitive_read_path_argument as sensitive_path_argument;
use glob_class::glob_class_matches;
use std::collections::{HashSet, VecDeque};
mod agent_root;
mod fd;
mod git_metadata;
mod glob_class;
pub(super) mod grep;
mod hint;
mod options;
mod rg;
mod rg_whitelist;
mod roots;
mod sibling;
mod tree;
mod walk_memo;
pub(super) use agent_root::{
    agent_root_listing, skill_link_resolves_over_home, skill_listing_root,
};
use options::unsafe_search_value;
pub(super) use rg::{rg_hidden_whitelist_reason, safe_rg_stdin_arguments};
pub(super) use sibling::named_path as sibling_repository_named_file;
pub(super) use tree::{
    safe_glob_operand, safe_literal_bracket_read_target, safe_literal_bracket_tree,
    safe_recursive_target, safe_recursive_target_through_links, safe_unmatched_glob_operand,
    SECRET_EXTENSIONS,
};
pub(super) use walk_memo::with_walk_memo;

/// A names-only walk (`find`) rooted at a project-metadata directory such as
/// `.github` inside a repository work tree, the session's own or a sibling
/// checkout. The root must be one a hidden-directory listing may name, every
/// hidden component of its canonical path a benign metadata name, and every
/// descendant must clear the recursive-listing screen.
pub(super) fn metadata_directory_walk(value: &str, context: ReadContext<'_>) -> bool {
    if value.split(['/', '\\']).any(|part| part == "..")
        || !super::read_paths::repository_hidden_directory(value, context.home_dir, context.cwd)
    {
        return false;
    }
    let Some(root) = tree::expanded_operand(value, context)
        .and_then(|root| std::fs::canonicalize(root).ok())
        .filter(|root| root.is_dir())
    else {
        return false;
    };
    root.components().all(|component| match component {
        std::path::Component::Normal(name) => name
            .to_str()
            .is_some_and(|name| !name.starts_with('.') || tree::hidden_allowed(name)),
        _ => true,
    }) && tree::walk(root, &[], &[], false, false)
}
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
        // A brace with no comma and no `..`, such as Git's `HEAD^{commit}` or
        // `@{u}`, is literal text to the shell and a single alternative to a
        // glob, so it is checked as its inner text: `{.env}` still names
        // `.env`. A `..` sequence such as `.en{v..v}` expands in bash, so it
        // keeps failing closed.
        if choices.len() == 1 && !choices[0].contains('{') && !choices[0].contains("..") {
            expanded.push(format!(
                "{}{}{}",
                &candidate[..open],
                choices[0],
                &candidate[close + 1..]
            ));
            continue;
        }
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
pub(super) fn glob_can_select_sensitive_path(value: &str) -> bool {
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
            let code_extension = component
                .rsplit_once('.')
                .is_some_and(|(_, extension)| guard_secure_fs::is_source_code_extension(extension));
            if !code_extension
                && guard_secure_fs::credential_path_markers()
                    .iter()
                    .any(|marker| {
                        glob_matches(bytes, marker.as_bytes())
                            || glob_intersects_prefix_family(bytes, format!("{marker}.").as_bytes())
                            || glob_intersects_contains_family(bytes, marker.as_bytes(), true)
                    })
            {
                return true;
            }
            // A literal source extension already lets `*.ts` through, so for
            // such a glob only the text before its first `*` can aim it at
            // `.env.` files: `.env*.ts` still refuses, `*.test.ts` does not.
            let env_scope = if code_extension {
                &bytes[..bytes
                    .iter()
                    .position(|character| *character == b'*')
                    .unwrap_or(bytes.len())]
            } else {
                bytes
            };
            let env_hint = hint::glob_constrained_lcs(env_scope, b".env.") >= 2;
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
    /// ripgrep `-g`/`--glob`: a leading `!` turns the glob into an exclusion,
    /// which only removes files from the walk and never selects new ones.
    RgGlob,
    Path,
    TypeGlob,
    /// ripgrep `-t`/`--type`: a built-in type name, whose globs may name
    /// hidden files.
    RgType,
    DirectoryAction,
    Other,
}
type ReadContext<'a> = super::PathContext<'a>;
fn short_search_option(
    argument: &str,
    dangerous: &[char],
    value_options: &[(char, SearchValueRole)],
    context: ReadContext<'_>,
) -> Result<(Option<SearchValueRole>, bool), ()> {
    for (offset, option) in argument[1..].char_indices() {
        if dangerous.contains(&option) {
            return Err(());
        }
        if let Some((_, role)) = value_options.iter().find(|(name, _)| *name == option) {
            let value_start = offset + option.len_utf8();
            let attached = &argument[1 + value_start..];
            if !attached.is_empty() && unsafe_search_value(*role, attached, context) {
                return Err(());
            }
            // `-f FILE` supplies the patterns as `-e` does.
            return Ok((
                attached.is_empty().then_some(*role),
                matches!(role, SearchValueRole::Pattern | SearchValueRole::Path),
            ));
        }
    }
    Ok((None, false))
}

pub(super) fn safe_search_arguments_with_context(
    executable: &str,
    arguments: &[String],
    context: ReadContext<'_>,
) -> bool {
    match executable {
        "rg" => rg::safe_rg_arguments(arguments, context),
        "fd" => fd::safe_fd_arguments(arguments, context),
        "grep" => grep::safe_grep_arguments(arguments, context),
        _ => false,
    }
}

pub(super) fn safe_rg_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: ReadContext<'_>,
) -> bool {
    rg::safe_rg_segment(model, segment, context)
}

pub(super) fn safe_grep_stdin_arguments(arguments: &[String]) -> bool {
    grep::safe_stdin_arguments(arguments)
}

#[cfg(test)]
mod tests {
    use super::glob_can_select_sensitive_path;

    #[test]
    fn brace_sequences_still_select_sensitive_names() {
        // Git's brace suffixes are one literal alternative.
        for literal in ["head^{commit}", "4dc51cdaa1^{tree}", "head@{0}", "@{u}"] {
            assert!(!glob_can_select_sensitive_path(literal), "{literal}");
        }
        // Bash expands a `..` sequence: `.en{v..v}` is `.env`.
        for selecting in [
            ".en{v..v}",
            ".npmr{c..c}",
            "config/.en{v..v}",
            ".en{v..v..1}",
            "{.env}",
            "{.env,readme.md}",
        ] {
            assert!(glob_can_select_sensitive_path(selecting), "{selecting}");
        }
    }
}
