use super::*;

// ---------------------------------------------------------------------------
// `_normalized_command_segments` and context machinery
// ---------------------------------------------------------------------------

// package_intent_parser.py `_normalized_command_segments`
pub(super) fn normalized_command_segments(
    command_text: &str,
    workspace: Option<&Path>,
    home_dir: Option<&Path>,
    environment: Option<&BTreeMap<String, String>>,
) -> Vec<CommandSegment> {
    let default_environment;
    let inherited_environment: &BTreeMap<String, String> = match environment {
        Some(env) => env,
        None => {
            default_environment = std::env::vars().collect::<BTreeMap<_, _>>();
            &default_environment
        }
    };
    let mut execution_context =
        model_shell_execution_context(command_text, workspace, workspace, home_dir);
    if !execution_context.complete && home_dir.is_some() {
        let home_context =
            model_shell_execution_context(command_text, home_dir, home_dir, home_dir);
        if home_context.complete
            && !home_context.segments.is_empty()
            && home_context.segments[0].directory_operation.as_deref() == Some("cd")
        {
            let target = home_context
                .segments
                .iter()
                .skip(1)
                .find_map(|segment| segment.effective_cwd.clone());
            if let Some(target) = target {
                let recovered = model_shell_execution_context(
                    command_text,
                    Some(target.as_path()),
                    Some(target.as_path()),
                    home_dir,
                );
                if recovered.complete {
                    execution_context = recovered;
                }
            }
        }
    }
    let control_shape: Vec<&'static str> = execution_context
        .segments
        .iter()
        .map(|segment| control_context_label(segment.control_operator().map(|s| s.as_str())))
        .collect();
    let mut segments: Vec<CommandSegment> = Vec::new();
    for context_segment in &execution_context.segments {
        let raw_segment: Vec<String> = context_segment.tokens.clone();
        let normalized_tokens = normalize_segment(&raw_segment);
        if normalized_tokens.is_empty() {
            continue;
        }
        let redacted_tokens = redacted_segment(&raw_segment);
        let (modeled_cwd, validation_reason) =
            validate_shell_execution_segment(&execution_context, context_segment);
        let (effective_path, path_source, effective_cwd, cwd_source) = match modeled_cwd {
            None => (
                None,
                "cwd_unresolved".to_owned(),
                None,
                validation_reason
                    .clone()
                    .or_else(|| context_segment.reason_code.clone())
                    .unwrap_or_else(|| "cwd_unresolved".to_owned()),
            ),
            Some(modeled_cwd) => effective_execution_context(
                &raw_segment,
                workspace,
                &modeled_cwd,
                &context_segment.cwd_source,
                inherited_environment,
            ),
        };
        let context_complete = validation_reason.is_none() && context_segment.complete;
        let opaque_binding =
            opaque_unresolved_context_binding(&raw_segment, &path_source, &cwd_source);
        let context_hash = execution_context_hash(
            &execution_context,
            context_segment,
            &control_shape,
            effective_cwd.as_deref(),
            &cwd_source,
            &path_source,
            opaque_binding.as_deref(),
        );
        segments.push(CommandSegment {
            tokens: normalized_tokens,
            redacted_tokens,
            effective_path,
            path_source,
            effective_cwd,
            cwd_source,
            context_hash,
            context_complete,
            context_reason_code: validation_reason.or_else(|| context_segment.reason_code.clone()),
        });
    }
    segments
}

// package_intent_parser.py `_effective_execution_context`
pub(super) fn effective_execution_context(
    raw_segment: &[String],
    workspace: Option<&Path>,
    initial_cwd: &Path,
    initial_cwd_source: &str,
    supplied_environment: &BTreeMap<String, String>,
) -> (Option<String>, String, Option<PathBuf>, String) {
    let mut effective_path: Option<String> = supplied_environment.get("PATH").cloned();
    let mut path_source = if effective_path.is_some() {
        "inherited".to_owned()
    } else {
        "inherited_unset".to_owned()
    };
    let mut effective_cwd: Option<PathBuf> = Some(initial_cwd.to_path_buf());
    let mut cwd_source = initial_cwd_source.to_owned();
    let _ = workspace;
    if raw_segment.is_empty() {
        return (
            effective_path
                .as_deref()
                .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
            path_source,
            effective_cwd,
            cwd_source,
        );
    }
    let mut index = 0usize;
    let (next_index, next_path, next_source) = consume_path_assignments(
        raw_segment,
        index,
        effective_path.clone(),
        &path_source,
        "inline",
        supplied_environment,
    );
    index = next_index;
    effective_path = next_path;
    path_source = next_source;
    if index >= raw_segment.len() {
        return (
            effective_path
                .as_deref()
                .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
            path_source,
            effective_cwd,
            cwd_source,
        );
    }
    let mut name = command_name(&raw_segment[index]);
    if name == "sudo" {
        return (
            None,
            "sudo_unresolved".to_owned(),
            effective_cwd,
            cwd_source,
        );
    }
    while matches!(name.as_str(), "command" | "time") {
        index += 1;
        if name == "command" {
            while index < raw_segment.len() && raw_segment[index].starts_with('-') {
                if raw_segment[index][1..].contains('p') {
                    effective_path = Some(default_path());
                    path_source = "command_default".to_owned();
                }
                index += 1;
            }
        } else if index < raw_segment.len() && raw_segment[index].starts_with('-') {
            return (
                None,
                "time_options_unresolved".to_owned(),
                effective_cwd,
                cwd_source,
            );
        }
        let (next_index, next_path, next_source) = consume_path_assignments(
            raw_segment,
            index,
            effective_path.clone(),
            &path_source,
            "inline",
            supplied_environment,
        );
        index = next_index;
        effective_path = next_path;
        path_source = next_source;
        if index >= raw_segment.len() {
            return (
                effective_path
                    .as_deref()
                    .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
                path_source,
                effective_cwd,
                cwd_source,
            );
        }
        name = command_name(&raw_segment[index]);
    }
    if name != "env" {
        return (
            effective_path
                .as_deref()
                .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
            path_source,
            effective_cwd,
            cwd_source,
        );
    }

    let mut inherited_environment = supplied_environment.clone();
    match &effective_path {
        None => {
            inherited_environment.remove("PATH");
        }
        Some(path) => {
            inherited_environment.insert("PATH".to_owned(), path.clone());
        }
    }
    let parsed_env = parse_env_wrapper(
        &raw_segment[index + 1..],
        Some(&inherited_environment),
        effective_cwd.as_deref(),
    );
    if !parsed_env.complete {
        return (
            None,
            format!(
                "env_{}",
                parsed_env.error.as_deref().unwrap_or("unresolved")
            ),
            effective_cwd,
            cwd_source,
        );
    }
    let path_was_unset = parsed_env
        .option_effects
        .unset_names
        .iter()
        .any(|n| n == "PATH");
    let path_assignment = parsed_env
        .environment_delta
        .assignments
        .iter()
        .rev()
        .find(|(n, _)| n == "PATH")
        .map(|(_, v)| v.clone());
    if let Some(search_path) = &parsed_env.option_effects.search_path {
        effective_path = expanded_path_assignment(
            search_path,
            effective_path.as_deref(),
            &inherited_environment,
        );
        path_source = if effective_path.is_some() {
            "env_search_path".to_owned()
        } else {
            "env_search_path_unresolved".to_owned()
        };
    } else if let Some(assignment) = &path_assignment {
        effective_path = expanded_path_assignment(
            assignment,
            effective_path.as_deref(),
            &inherited_environment,
        );
        path_source = if effective_path.is_some() {
            "env".to_owned()
        } else {
            "env_unresolved".to_owned()
        };
    } else if parsed_env.option_effects.ignore_environment || path_was_unset {
        effective_path = Some(default_path());
        path_source = "env_default".to_owned();
    }
    if let Some(chdir) = &parsed_env.option_effects.chdir {
        if chdir.contains('$') || chdir.contains('\0') {
            cwd_source = "env_chdir_unresolved".to_owned();
        } else if let Some(env_cwd) = &parsed_env.effective_cwd {
            match env_cwd.canonicalize() {
                Ok(resolved) => {
                    effective_cwd = Some(resolved);
                    cwd_source = "env_chdir".to_owned();
                }
                Err(_) => {
                    cwd_source = "env_chdir_unresolved".to_owned();
                }
            }
        }
    }
    (
        effective_path
            .as_deref()
            .map(|path| path_for_resolution(path, effective_cwd.as_deref())),
        path_source,
        effective_cwd,
        cwd_source,
    )
}

// package_intent_parser.py `_execution_context_hash`
#[allow(clippy::too_many_arguments)]
pub(super) fn execution_context_hash(
    context: &ShellExecutionContext,
    segment: &ShellExecutionSegment,
    control_shape: &[&'static str],
    effective_cwd: Option<&Path>,
    cwd_source: &str,
    path_source: &str,
    opaque_context_binding: Option<&str>,
) -> String {
    let mut payload = Map::new();
    payload.insert(
        "schema".to_owned(),
        json!("local-package-execution-context-v2"),
    );
    payload.insert("control_shape".to_owned(), json!(control_shape));
    payload.insert("segment_index".to_owned(), json!(segment.segment_index));
    payload.insert("control_before".to_owned(), json!(segment.control_before));
    payload.insert("control_after".to_owned(), json!(segment.control_after));
    payload.insert(
        "workspace_root".to_owned(),
        context
            .workspace_root
            .as_ref()
            .map(|p| json!(p.to_string_lossy()))
            .unwrap_or(Value::Null),
    );
    payload.insert(
        "workspace_identity".to_owned(),
        shell_path_identity_payload(context.workspace_identity.as_ref()).unwrap_or(Value::Null),
    );
    payload.insert(
        "effective_cwd".to_owned(),
        effective_cwd
            .map(|p| json!(p.to_string_lossy()))
            .unwrap_or(Value::Null),
    );
    payload.insert(
        "cwd_identity".to_owned(),
        shell_path_identity_payload(segment.cwd_identity.as_ref()).unwrap_or(Value::Null),
    );
    payload.insert(
        "cwd_path_proofs".to_owned(),
        Value::Array(
            segment
                .cwd_path_proofs
                .iter()
                .map(|proof| {
                    let mut p = Map::new();
                    p.insert(
                        "lexical_path".to_owned(),
                        json!(proof.lexical_path.to_string_lossy()),
                    );
                    p.insert(
                        "resolved_path".to_owned(),
                        json!(proof.resolved_path.to_string_lossy()),
                    );
                    p.insert(
                        "identity".to_owned(),
                        shell_path_identity_payload(Some(&proof.identity)).unwrap_or(Value::Null),
                    );
                    Value::Object(p)
                })
                .collect(),
        ),
    );
    payload.insert(
        "directory_stack".to_owned(),
        Value::Array(
            segment
                .directory_stack
                .iter()
                .map(|p| json!(p.to_string_lossy()))
                .collect(),
        ),
    );
    payload.insert("cwd_source".to_owned(), json!(cwd_source));
    payload.insert("path_source".to_owned(), json!(path_source));
    payload.insert(
        "opaque_context_binding".to_owned(),
        opaque_context_binding
            .map(|s| json!(s))
            .unwrap_or(Value::Null),
    );
    // Python `json.dumps(payload, sort_keys=True, separators=(",", ":"))` —
    // `serde_json::to_string` emits compact JSON; `Value::Object` keys are
    // already BTreeMap-sorted.
    let payload_str = serde_json::to_string(&Value::Object(payload)).unwrap_or_default();
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(payload_str.as_bytes()))
    )
}
