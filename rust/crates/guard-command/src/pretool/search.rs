use super::sensitive_read_path_argument as sensitive_path_argument;
use glob_class::glob_class_matches;
use std::collections::{HashSet, VecDeque};
mod agent_root;
mod fd;
mod git_metadata;
mod glob_class;
pub(super) mod grep;
mod hint;
mod names_only;
mod options;
#[cfg(test)]
mod repeat_walk_tests;
mod rg;
mod rg_whitelist;
mod roots;
mod sibling;
mod tree;
mod walk_memo;
pub(super) use agent_root::{
    agent_root_listing, skill_link_resolves_over_home, skill_listing_root,
};
pub(super) use git_metadata::safe_git_entry;
use options::unsafe_search_value;
pub(super) use rg::{rg_hidden_whitelist_reason, safe_rg_stdin_arguments};
pub(super) use sibling::named_path as sibling_repository_named_file;
pub(super) use tree::{
    glob_matches_nothing, safe_glob_operand, safe_literal_bracket_read_target,
    safe_literal_bracket_tree, safe_recursive_listing_target, safe_recursive_target,
    safe_recursive_target_through_links, safe_unmatched_glob_operand, SECRET_EXTENSIONS,
};
#[cfg(test)]
pub(super) use walk_memo::{count_walk, take_walks};
pub(super) use walk_memo::{memoized_keyed, memoized_proof, with_walk_memo};

/// Whether no step of `model` creates a filesystem entry.
///
/// A read of a path with nothing at it is proven only while it stays
/// missing: a peer step that writes a file, makes a directory or links one
/// (`ln -s <dir> <repo>/cfg && cat <repo>/cfg/id_rsa`) would put something
/// there before the read opens it. `grep` asks the same question of its own
/// peers; a whole-command answer serves the readers that prove one operand
/// at a time.
pub(super) fn command_creates_nothing(model: &crate::CanonicalCommandV1) -> bool {
    model.segments.iter().all(grep::creates_nothing)
}

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
/// The one brace pair bash would expand next, as `(open, close)` byte
/// offsets. Bash pairs a `}` with the nearest `{` to its left, so an opening
/// brace that never closes is skipped rather than swallowing the pair that
/// follows it: `{x/{.gnupg,b}` is `{x/.gnupg {x/b`, and the component
/// `.gnupg` is exactly what a sensitive-path check has to see. Pairing the
/// first `{` with the first `}` instead produced `x/{.gnupg`, which matches
/// no marker. A `}` with no `{` anywhere to its left is literal text to bash,
/// which still expands the pair after it (`}{.env,x}` is `}.env }x`), so such
/// a brace is passed over rather than ending the search for a pair.
fn innermost_brace_pair(candidate: &str) -> Option<(usize, usize)> {
    candidate
        .match_indices('}')
        .find_map(|(close, _)| candidate[..close].rfind('{').map(|open| (open, close)))
}

/// The same candidate with the `}` at `close` taken as the literal text an
/// escaped brace leaves behind. Bash carries the pair on to the next `}`, so
/// this reading exists only when a comma and a later `}` follow, and only
/// when the next character is not itself a `}`: a brace that closes straight
/// into another one is the inner half of a nested pair such as a Go template
/// `{{.Names}},{{.Status}}`, not an escape. `None` otherwise, which is the
/// ordinary case.
fn escaped_close_reading(candidate: &str, close: usize) -> Option<String> {
    if candidate[close + 1..].starts_with('}') {
        return None;
    }
    let comma = candidate[close + 1..].find(',')? + close + 1;
    candidate[comma..].find('}')?;
    Some(format!(
        "{}{}",
        &candidate[..close],
        &candidate[close + 1..]
    ))
}

fn expand_brace_globs(pattern: &str) -> Option<Vec<String>> {
    // The flag beside each candidate records whether it still carries the
    // braces of the word as written. Only such a candidate can have held the
    // backslash the tokenizer dropped, and a comma expansion hands that
    // standing on to every part it produces.
    let mut expanded = vec![(pattern.to_owned(), true)];
    for _ in 0..8 {
        // A brace with no `}` after it expands to nothing: bash leaves `a{b`
        // and a search pattern such as `json({ error` as the literal text it
        // was written as. Reading that shape as a glob nobody could expand
        // refused every search whose pattern held an unbalanced brace, so a
        // candidate ends the pass unless one of its braces could still open
        // an alternative.
        let Some(index) = expanded
            .iter()
            .position(|(candidate, _)| innermost_brace_pair(candidate).is_some())
        else {
            return Some(
                expanded
                    .into_iter()
                    .map(|(candidate, _)| candidate)
                    .collect(),
            );
        };
        let (candidate, as_written) = expanded.swap_remove(index);
        let (open, close) = innermost_brace_pair(&candidate)?;
        let choices: Vec<&str> = candidate[open + 1..close].split(',').collect();
        // A brace with no comma and no `..`, such as Git's `HEAD^{commit}`,
        // `@{u}` or a Go template `{{.Server.Version}}`, is literal text to the
        // shell and a single alternative to a glob, so it is checked as its
        // inner text: `{.env}` and `{{.env}}` still name `.env`. A `..`
        // sequence such as `.en{v..v}` expands in bash, so it keeps failing
        // closed.
        if choices.len() == 1 && !choices[0].contains("..") {
            let trimmed = choices[0].trim_start_matches('{');
            if !trimmed.contains('{') {
                let nested_braces = choices[0].len() - trimmed.len();
                let closing = "}".repeat(nested_braces);
                let suffix = candidate[close + 1..]
                    .strip_prefix(closing.as_str())
                    .unwrap_or(&candidate[close + 1..]);
                // The tokenizer drops a backslash before it reaches here, so
                // `z{prefix/{x\},.env}` arrives as `z{prefix/{x},.env}`. To
                // bash that `}` was literal text, which left the pair opening
                // further left and the words `z{prefix/x}` and `z{prefix/.env`.
                // Reading only the inner pair would hide that second word, so
                // the spelling with this brace taken as literal is carried
                // alongside and screened too. Only the word as written can
                // have carried the backslash, so a candidate this branch has
                // already rewritten yields no further reading; generating one
                // from every rewrite makes an ordinary multi-part template
                // outgrow the budget below and fail closed.
                if as_written {
                    if let Some(escaped) = escaped_close_reading(&candidate, close) {
                        expanded.push((escaped, false));
                    }
                }
                expanded.push((format!("{}{trimmed}{suffix}", &candidate[..open],), false));
                continue;
            }
        }
        if choices.len() < 2 || expanded.len() + choices.len() > 16 {
            return None;
        }
        for choice in choices {
            expanded.push((
                format!(
                    "{}{}{}",
                    &candidate[..open],
                    choice,
                    &candidate[close + 1..]
                ),
                as_written,
            ));
        }
    }
    None
}
pub(super) fn glob_can_select_sensitive_path(value: &str) -> bool {
    glob_selects_sensitive_path(value, true)
}
/// The marker tests `glob_can_select_sensitive_path` makes about the glob's
/// own text, leaving out the two families that ask only whether some longer
/// string the glob could match would start with, or hold, a marker. A path
/// operand is refused on those wider questions because another proof can
/// still clear it. A pattern has no such proof, and the wider questions
/// refuse every regex with a `.*` in it: `cookie.*name` or `auth.*provider`
/// reaches a credential only if a file named `cookie.<something>name` is
/// there to be expanded onto the command line.
///
/// A bare `<marker>.<anything>` word does reach one: `credentials.*` expands
/// to `credentials.json credentials.yml`, and the second is the file `grep`
/// opens. `<marker>.x` stands in for that shape, which the regexes miss.
pub(super) fn literal_glob_names_sensitive_path(value: &str) -> bool {
    glob_selects_sensitive_path(value, false)
}
fn glob_selects_sensitive_path(value: &str, path_operand: bool) -> bool {
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
                            || glob_matches(bytes, format!("{marker}.x").as_bytes())
                            || (path_operand
                                && (glob_intersects_prefix_family(
                                    bytes,
                                    format!("{marker}.").as_bytes(),
                                ) || glob_intersects_contains_family(
                                    bytes,
                                    marker.as_bytes(),
                                    true,
                                )))
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
                || (path_operand
                    && family_hint
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

pub(super) fn safe_fd_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: ReadContext<'_>,
) -> bool {
    fd::safe_fd_segment(model, segment, context)
}

pub(super) fn safe_rg_segment(
    model: &crate::CanonicalCommandV1,
    segment: &crate::CommandSegmentV1,
    context: ReadContext<'_>,
) -> bool {
    rg::safe_rg_segment(model, segment, context)
}

pub(super) fn safe_grep_stdin_arguments(arguments: &[String], literal_words: &[String]) -> bool {
    grep::safe_stdin_arguments(arguments, literal_words)
}

#[cfg(test)]
#[path = "search_tests.rs"]
mod tests;
