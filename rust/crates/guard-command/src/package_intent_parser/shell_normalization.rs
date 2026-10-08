use super::*;

// package_intent_parser.py `_raw_command_segments`
#[allow(dead_code)]
pub(super) fn raw_command_segments(tokens: &[String]) -> Vec<Vec<String>> {
    raw_command_segments_with_operators(tokens)
        .into_iter()
        .map(|(segment, _)| segment)
        .collect()
}

// package_intent_parser.py `_raw_command_segments_with_operators`
pub(super) fn raw_command_segments_with_operators(
    tokens: &[String],
) -> Vec<(Vec<String>, Option<String>)> {
    let mut segments: Vec<(Vec<String>, Option<String>)> = Vec::new();
    let mut segment: Vec<String> = Vec::new();
    for token in tokens {
        if CONTROL_TOKENS.contains(&token.as_str()) {
            if !segment.is_empty() {
                segments.push((std::mem::take(&mut segment), Some(token.clone())));
            }
            segment.clear();
            continue;
        }
        segment.push(token.clone());
    }
    if !segment.is_empty() {
        segments.push((segment, None));
    }
    segments
}

// package_intent_parser.py `_normalize_segment`
pub(super) fn normalize_segment(raw_segment: &[String]) -> Vec<String> {
    if let Some(substitution_segment) = shell_substitution_segment(raw_segment) {
        return without_fd_merge_redirections(&substitution_segment);
    }
    if command_builtin_is_lookup(&strip_command_lookup_prefixes(raw_segment.to_vec())) {
        return Vec::new();
    }
    let mut segment = without_fd_merge_redirections(&strip_wrapper_tokens(raw_segment.to_vec()));
    if segment.len() >= 3
        && PYTHON_EXECUTABLES.contains(command_name(&segment[0]).as_str())
        && segment[1] == "-m"
    {
        segment = segment[2..].to_vec();
    }
    segment
}

// package_intent_parser.py `_consume_path_assignments`
pub(super) fn consume_path_assignments(
    tokens: &[String],
    mut index: usize,
    mut current_path: Option<String>,
    current_source: &str,
    direct_source: &str,
    environment: &BTreeMap<String, String>,
) -> (usize, Option<String>, String) {
    let mut path_source = current_source.to_owned();
    while index < tokens.len() && ENV_ASSIGNMENT_RE.is_match(&tokens[index]) {
        let (name, _, value) = {
            let parts: Vec<&str> = tokens[index].splitn(2, '=').collect();
            (
                parts.first().copied().unwrap_or(""),
                "",
                parts.get(1).copied().unwrap_or(""),
            )
        };
        if name == "PATH" {
            current_path = expanded_path_assignment(value, current_path.as_deref(), environment);
            path_source = if current_path.is_some() {
                direct_source.to_owned()
            } else {
                format!("{direct_source}_unresolved")
            };
        }
        index += 1;
    }
    (index, current_path, path_source)
}

// package_intent_parser.py `_expanded_path_assignment`
pub(super) fn expanded_path_assignment(
    value: &str,
    current_path: Option<&str>,
    environment: &BTreeMap<String, String>,
) -> Option<String> {
    let mut expansion_environment = environment.clone();
    expansion_environment.insert("PATH".to_owned(), current_path.unwrap_or("").to_owned());
    let expanded = ENV_REFERENCE_RE
        .replace_all(value, |caps: &regex::Captures<'_>| {
            let name = caps
                .name("braced")
                .or_else(|| caps.name("plain"))
                .map(|m| m.as_str())
                .unwrap_or("");
            expansion_environment.get(name).cloned().unwrap_or_else(|| {
                caps.get(0)
                    .map(|m| m.as_str().to_owned())
                    .unwrap_or_default()
            })
        })
        .into_owned();
    if expanded.contains('$') || expanded.contains('\0') {
        return None;
    }
    Some(expanded)
}

// package_intent_parser.py `_package_source_env_assignment`
pub(super) fn package_source_env_assignment(token: &str) -> bool {
    let mut parts = token.splitn(2, '=');
    let name = parts.next().unwrap_or("");
    let value = parts.next();
    match value {
        Some(value) => {
            !value.is_empty() && PACKAGE_SOURCE_ENV_NAMES.contains(&*name.to_uppercase())
        }
        None => false,
    }
}

// package_intent_parser.py `_updated_effective_cwd`
#[allow(dead_code)]
pub(super) fn updated_effective_cwd(current_cwd: &Path, value: &str) -> (PathBuf, String) {
    let expanded = expand_env_vars(value);
    if expanded.is_empty() || expanded.contains('$') || expanded.contains('\0') {
        return (current_cwd.to_path_buf(), "env_chdir_unresolved".to_owned());
    }
    let mut candidate = expand_user(&expanded);
    if !candidate.is_absolute() {
        candidate = current_cwd.join(&candidate);
    }
    match candidate.canonicalize() {
        Ok(resolved) => (resolved, "env_chdir".to_owned()),
        Err(_) => (current_cwd.to_path_buf(), "env_chdir_unresolved".to_owned()),
    }
}

/// `os.path.expandvars` equivalent — substitute `$NAME`/`${NAME}` against the
/// process environment.
pub(super) fn expand_env_vars(value: &str) -> String {
    ENV_REFERENCE_RE
        .replace_all(value, |caps: &regex::Captures<'_>| {
            let name = caps
                .name("braced")
                .or_else(|| caps.name("plain"))
                .map(|m| m.as_str())
                .unwrap_or("");
            std::env::var(name).unwrap_or_default()
        })
        .into_owned()
}

/// `Path.expanduser` equivalent — `~`/`~user` prefix expansion.
pub(super) fn expand_user(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix('~') {
        if rest.is_empty() || rest.starts_with('/') {
            if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
            {
                return PathBuf::from(home).join(rest.trim_start_matches('/'));
            }
        }
        // `~name/` form — not resolved without pwd database; leave as-is.
        return PathBuf::from(path);
    }
    PathBuf::from(path)
}

// package_intent_parser.py `_path_for_resolution`
pub(super) fn path_for_resolution(path_value: &str, effective_cwd: Option<&Path>) -> String {
    let mut rendered: Vec<String> = Vec::new();
    for entry in path_value.split(':') {
        let mut rendered_entry = entry.to_owned();
        if rendered_entry.is_empty() {
            rendered_entry = ".".to_owned();
        }
        let mut path = PathBuf::from(&rendered_entry);
        if !path.is_absolute() {
            if let Some(cwd) = effective_cwd {
                path = cwd.join(&path);
            }
        }
        rendered.push(path.to_string_lossy().into_owned());
    }
    rendered.join(":")
}

// package_intent_parser.py `_command_builtin_is_lookup`
pub(super) fn command_builtin_is_lookup(segment: &[String]) -> bool {
    if segment.is_empty() || command_name(&segment[0]) != "command" {
        return false;
    }
    let mut saw_lookup = false;
    let mut index = 1usize;
    while index < segment.len() && segment[index].starts_with('-') {
        let option = &segment[index];
        saw_lookup = saw_lookup || option[1..].contains('v') || option[1..].contains('V');
        index += 1;
    }
    let operands: Vec<&String> = segment[index..]
        .iter()
        .filter(|token| !token.contains('>') && !token.contains('<'))
        .collect();
    saw_lookup && operands.len() == 1
}

// package_intent_parser.py `_shell_substitution_segment`
pub(super) fn shell_substitution_segment(segment: &[String]) -> Option<Vec<String>> {
    for (index, token) in segment.iter().enumerate() {
        if !token.contains('`') && !token.contains("$(") {
            continue;
        }
        let mut best: Option<(usize, usize)> = None;
        for marker in ["`", "$("] {
            if let Some(position) = token.find(marker) {
                let candidate = (position, marker.len());
                if best.map(|(p, _)| position < p).unwrap_or(true) {
                    best = Some(candidate);
                }
            }
        }
        let (position, marker_len) = best?;
        let command = &token[position + marker_len..];
        let mut seed = vec![command.to_owned()];
        seed.extend_from_slice(&segment[index + 1..]);
        let normalized = if command.is_empty() {
            Vec::new()
        } else {
            strip_wrapper_tokens(seed)
        };
        if !normalized.is_empty()
            && PACKAGE_COMMAND_NAMES.contains(command_name(&normalized[0]).as_str())
        {
            return Some(normalized);
        }
    }
    None
}

// package_intent_parser.py `_without_fd_merge_redirections`
pub(super) fn without_fd_merge_redirections(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .filter(|token| token.as_str() != "1>&2" && token.as_str() != "2>&1")
        .cloned()
        .collect()
}

// package_intent_parser.py `_strip_wrapper_tokens`
pub(super) fn strip_wrapper_tokens(mut segment: Vec<String>) -> Vec<String> {
    while !segment.is_empty() {
        if ENV_ASSIGNMENT_RE.is_match(&segment[0]) {
            segment.remove(0);
            continue;
        }
        let name = command_name(&segment[0]);
        if name == "sudo" {
            segment = strip_sudo_prefix(&segment[1..]);
            continue;
        }
        if name == "env" {
            segment = strip_env_prefix(&segment[1..]);
            continue;
        }
        if matches!(name.as_str(), "command" | "time") {
            segment = strip_plain_wrapper_flags(&segment[1..]);
            continue;
        }
        break;
    }
    segment
}

// package_intent_parser.py `_strip_command_lookup_prefixes`
pub(super) fn strip_command_lookup_prefixes(mut segment: Vec<String>) -> Vec<String> {
    while !segment.is_empty() {
        if ENV_ASSIGNMENT_RE.is_match(&segment[0]) {
            if segment[0].contains('`') || segment[0].contains("$(") {
                return segment;
            }
            segment.remove(0);
            continue;
        }
        if command_name(&segment[0]) == "time" {
            segment = strip_plain_wrapper_flags(&segment[1..]);
            continue;
        }
        break;
    }
    segment
}

// package_intent_parser.py `_strip_sudo_prefix`
pub(super) fn strip_sudo_prefix(tokens: &[String]) -> Vec<String> {
    let mut index = 0usize;
    while index < tokens.len() {
        let token = &tokens[index];
        if !token.starts_with('-') {
            break;
        }
        if matches!(
            token.as_str(),
            "-u" | "-g" | "-h" | "-p" | "-r" | "-t" | "-C"
        ) && index + 1 < tokens.len()
        {
            index += 2;
            continue;
        }
        index += 1;
    }
    tokens[index..].to_vec()
}

// package_intent_parser.py `_strip_redaction_wrappers`
pub(super) fn strip_redaction_wrappers(mut segment: Vec<String>) -> Vec<String> {
    let mut preserved_env: Vec<String> = Vec::new();
    while !segment.is_empty() {
        if ENV_ASSIGNMENT_RE.is_match(&segment[0]) {
            if package_source_env_assignment(&segment[0]) {
                preserved_env.push(segment[0].clone());
            }
            segment.remove(0);
            continue;
        }
        let name = command_name(&segment[0]);
        if name == "sudo" {
            segment = strip_sudo_prefix(&segment[1..]);
            continue;
        }
        if name == "env" {
            let (env_preserved, next) = strip_env_prefix_for_redaction(&segment[1..]);
            preserved_env.extend(env_preserved);
            segment = next;
            continue;
        }
        if matches!(name.as_str(), "command" | "time") {
            segment = strip_plain_wrapper_flags(&segment[1..]);
            continue;
        }
        break;
    }
    preserved_env.extend(segment);
    preserved_env
}

// package_intent_parser.py `_strip_plain_wrapper_flags`
pub(super) fn strip_plain_wrapper_flags(tokens: &[String]) -> Vec<String> {
    let mut index = 0usize;
    while index < tokens.len() && tokens[index].starts_with('-') {
        index += 1;
    }
    tokens[index..].to_vec()
}

// package_intent_parser.py `_strip_env_prefix`
pub(super) fn strip_env_prefix(tokens: &[String]) -> Vec<String> {
    let parsed = parse_env_wrapper(tokens, None, None);
    if parsed.complete {
        parsed.executable_argv
    } else {
        Vec::new()
    }
}

// package_intent_parser.py `_strip_env_prefix_for_redaction`
pub(super) fn strip_env_prefix_for_redaction(tokens: &[String]) -> (Vec<String>, Vec<String>) {
    let parsed = parse_env_wrapper(tokens, None, None);
    if !parsed.complete {
        return (Vec::new(), Vec::new());
    }
    let preserved_env: Vec<String> = parsed
        .environment_delta
        .assignments
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .filter(|token| package_source_env_assignment(token))
        .collect();
    (preserved_env, parsed.executable_argv)
}
