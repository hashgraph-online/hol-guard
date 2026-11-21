use super::*;

// package_intent_parser.py `_redacted_segment`
pub(super) fn redacted_segment(raw_segment: &[String]) -> Vec<String> {
    if let Some(substitution_segment) = shell_substitution_segment(raw_segment) {
        return without_fd_merge_redirections(&substitution_segment);
    }
    if command_builtin_is_lookup(&strip_command_lookup_prefixes(raw_segment.to_vec())) {
        return Vec::new();
    }
    let mut segment =
        without_fd_merge_redirections(&strip_redaction_wrappers(raw_segment.to_vec()));
    if segment.len() >= 3
        && PYTHON_EXECUTABLES.contains(command_name(&segment[0]).as_str())
        && segment[1] == "-m"
    {
        segment = segment[2..].to_vec();
    }
    redact_local_source_tokens(&segment)
}

// package_intent_parser.py `_redact_local_source_tokens`
pub(super) fn redact_local_source_tokens(tokens: &[String]) -> Vec<String> {
    let mut redacted: Vec<String> = Vec::new();
    let javascript_manager = tokens.first().is_some_and(|token| {
        matches!(
            command_name(token).as_str(),
            "npm" | "pnpm" | "yarn" | "bun" | "npx" | "bunx"
        )
    });
    let mut index = 0;
    while index < tokens.len() {
        let token = &tokens[index];
        if token == "--path" && index + 1 < tokens.len() {
            redacted.push("--path".to_owned());
            redacted.push("<local-path>".to_owned());
            index += 2;
            continue;
        }
        if token.starts_with("--path=") {
            redacted.push("--path=<local-path>".to_owned());
            index += 1;
            continue;
        }
        if package_source_env_assignment(token) {
            if let Some((name, value)) = token.split_once('=') {
                if value.contains("://") || value.contains("git@") || value.contains("file:") {
                    redacted.push(format!("{name}=[REDACTED_URL]"));
                    index += 1;
                    continue;
                }
            }
        }
        if token.contains("://") || token.contains("git@") || token.contains("file:") {
            let git_source = javascript_manager
                && crate::npm_source_spec::parse_npm_source_spec(Some(token))
                    .is_some_and(|source| source.is_git());
            // Git approval fingerprints need the validated repository spelling.
            // Other URLs retain blanket redaction; credentials never survive.
            redacted.push(if git_source {
                sanitize_url(token)
            } else {
                "[REDACTED_URL]".to_owned()
            });
        } else {
            redacted.push(token.clone());
        }
        index += 1;
    }
    redacted
}

// package_intent_parser.py `_redacted_command_text`
#[allow(dead_code)]
pub(super) fn redacted_command_text(tokens: &[String]) -> String {
    crate::command_launcher_floors::shlex_join(&redact_local_source_tokens(tokens))
}

// package_intent_parser.py `_rebase_intent_paths`
pub(super) fn rebase_intent_paths(
    mut intent: PackageIntent,
    from_directory: &Path,
    workspace: Option<&Path>,
) -> PackageIntent {
    let rebase = |paths: &[String]| -> Vec<String> {
        paths
            .iter()
            .map(|path| {
                let absolute = from_directory.join(path);
                match workspace {
                    Some(workspace) => {
                        match absolute
                            .canonicalize()
                            .or_else(|_| Ok(absolute.clone()))
                            .and_then(|p| {
                                p.strip_prefix(expand_resolve(workspace))
                                    .map(|r| r.to_path_buf())
                                    .map_err(|_| std::io::Error::other(""))
                            }) {
                            Ok(rel) => rel.to_string_lossy().into_owned(),
                            Err(_) => path.clone(),
                        }
                    }
                    None => path.clone(),
                }
            })
            .collect()
    };
    intent.manifest_paths = rebase(&intent.manifest_paths);
    intent.lockfile_paths = rebase(&intent.lockfile_paths);
    intent
}

pub(super) fn expand_resolve(path: &Path) -> PathBuf {
    expand_user(&path.to_string_lossy())
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
}

// package_intent_parser.py `_normalized_command_tokens`
#[allow(dead_code)]
pub(super) fn normalized_command_tokens(command_text: &str) -> Vec<Vec<String>> {
    normalized_command_segments(command_text, None, None, None)
        .into_iter()
        .map(|segment| segment.tokens)
        .collect()
}

// package_intent_parser.py `_combine_package_intents`
pub(super) fn combine_package_intents(intents: &[PackageIntent]) -> Option<PackageIntent> {
    let meaningful: Vec<&PackageIntent> = intents
        .iter()
        .filter(|intent| !intent.command_tokens.is_empty())
        .collect();
    match meaningful.len() {
        0 => None,
        1 => Some(meaningful[0].clone()),
        _ => {
            let mut combined = meaningful[0].clone();
            combined.intent_kind = combined_intent_kind(&meaningful);
            combined.package_manager = combined_package_manager(&meaningful);
            combined.command_tokens = meaningful
                .iter()
                .flat_map(|intent| intent.command_tokens.iter().cloned())
                .collect();
            combined.redacted_command = meaningful
                .iter()
                .map(|intent| intent.redacted_command.clone())
                .collect::<Vec<_>>()
                .join(" ; ");
            combined.targets = meaningful
                .iter()
                .flat_map(|intent| intent.targets.iter().cloned())
                .collect();
            combined.manifest_paths = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.manifest_paths.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.lockfile_paths = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.lockfile_paths.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.flags = unique_joined_tokens(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.flags.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.notes = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.notes.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.local_executions = meaningful
                .iter()
                .flat_map(|intent| intent.local_executions.iter().cloned())
                .collect();
            combined.execution_context_hashes = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.execution_context_hashes.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.execution_context_cwds = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.execution_context_cwds.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            combined.execution_context_reason_codes = unique_joined_strings(
                &meaningful
                    .iter()
                    .flat_map(|intent| intent.execution_context_reason_codes.iter().cloned())
                    .collect::<Vec<_>>(),
            );
            Some(combined)
        }
    }
}

// package_intent_parser.py `_combined_intent_kind`
pub(super) fn combined_intent_kind(intents: &[&PackageIntent]) -> IntentKind {
    let kinds: HashSet<&str> = intents.iter().map(|intent| intent.intent_kind).collect();
    if kinds.len() == 1 {
        intents[0].intent_kind
    } else if kinds.contains("install") {
        "install"
    } else if kinds.contains("execute") {
        "execute"
    } else {
        "sync"
    }
}

// package_intent_parser.py `_combined_package_manager`
pub(super) fn combined_package_manager(intents: &[&PackageIntent]) -> String {
    let managers: HashSet<&str> = intents
        .iter()
        .map(|intent| intent.package_manager.as_str())
        .collect();
    if managers.len() == 1 {
        intents[0].package_manager.clone()
    } else {
        "multi".to_owned()
    }
}

// package_intent_parser.py `_unique_joined_strings`
pub(super) fn unique_joined_strings(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value.clone());
        }
    }
    out
}

// package_intent_parser.py `_unique_joined_tokens`
pub(super) fn unique_joined_tokens(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value.clone());
        }
    }
    out
}
