use super::*;

// package_intent_parser.py `_stat_identity`
#[cfg(unix)]
pub(super) fn stat_identity(result: &std::fs::Metadata) -> String {
    [
        result.dev(),
        result.ino(),
        result.mode() as u64 & 0o7777,
        result.size(),
        result.mtime_nsec() as u64,
        result.ctime_nsec() as u64,
    ]
    .iter()
    .map(|value| value.to_string())
    .collect::<Vec<_>>()
    .join(":")
}

#[cfg(windows)]
pub(super) fn stat_identity(result: &std::fs::Metadata) -> String {
    // Stable std surface only: `size`/`last_write_time` live on `MetadataExt`;
    // `file_attributes` mirrors st_mode bits used downstream. We keep the
    // tuple shape identical so the identity string remains a positional
    // contract — digests diverge across OSes either way, which Python already
    // tolerates (stat fields differ across platforms).
    [
        0u64, // no stable volume-serial equivalent
        0u64, // no stable file-index equivalent
        result.file_attributes() as u64 & 0o7777,
        result.len(),
        result.last_write_time(),
        result.last_write_time(),
    ]
    .iter()
    .map(|value| value.to_string())
    .collect::<Vec<_>>()
    .join(":")
}

// package_intent_parser.py `_path_identity`
pub(super) fn path_identity(path: &Path) -> Option<String> {
    std::fs::metadata(path)
        .ok()
        .map(|metadata| stat_identity(&metadata))
}

// package_intent_parser.py `_execution_display_path`
pub(super) fn execution_display_path(workspace: &Path, path: &Path) -> String {
    match path.strip_prefix(expand_resolve(workspace)) {
        Ok(rel) => rel.to_string_lossy().replace('\\', "/"),
        Err(_) => path.to_string_lossy().into_owned(),
    }
}

// package_intent_parser.py `_opaque_unresolved_context_binding`
pub(super) fn opaque_unresolved_context_binding(
    raw_segment: &[String],
    path_source: &str,
    cwd_source: &str,
) -> Option<String> {
    if !(path_source.contains("unresolved")
        || path_source == "inherited_unset"
        || cwd_source.contains("unresolved")
        || cwd_source.contains("failed"))
    {
        return None;
    }
    let sensitive_context = raw_segment.join("\0");
    let mac = hmac_sha256(&EXECUTION_CONTEXT_HMAC_KEY, sensitive_context.as_bytes());
    Some(hex::encode(mac))
}

// package_intent_parser.py `_typescript_launch_inputs`
pub(super) fn typescript_launch_inputs(
    tokens: &[String],
    evidence: &LocalPackageExecutionEvidence,
) -> TypeScriptLaunchInputs {
    let manager = &evidence.manager;
    let executable = &evidence.local_executable;
    let available_manifests: Vec<&PackageExecutionFileEvidence> = evidence
        .manifests
        .iter()
        .filter(|item| {
            item.status == "available"
                && item.resolved_path.is_some()
                && item.content_hash.is_some()
        })
        .collect();
    let available_lockfiles: Vec<&PackageExecutionFileEvidence> = evidence
        .lockfiles
        .iter()
        .filter(|item| {
            item.status == "available"
                && item.resolved_path.is_some()
                && item.content_hash.is_some()
        })
        .collect();
    TypeScriptLaunchInputs {
        tokens: tokens.to_vec(),
        manager_name: evidence.manager_name.clone(),
        local_only_requested: evidence.local_only_requested,
        package_name: evidence.package_name.clone(),
        executable_name: evidence.executable_name.clone(),
        declared_version: evidence.declared_version.clone(),
        manager_path: if manager.as_ref().map(|m| m.status) == Some("available") {
            manager.as_ref().and_then(|m| m.resolved_path.clone())
        } else {
            None
        },
        manager_hash: if manager.as_ref().map(|m| m.status) == Some("available") {
            manager.as_ref().and_then(|m| m.content_hash.clone())
        } else {
            None
        },
        executable_path: if executable.as_ref().map(|e| e.status) == Some("available") {
            executable.as_ref().and_then(|e| e.resolved_path.clone())
        } else {
            None
        },
        executable_hash: if executable.as_ref().map(|e| e.status) == Some("available") {
            executable.as_ref().and_then(|e| e.content_hash.clone())
        } else {
            None
        },
        manifest_paths: available_manifests
            .iter()
            .filter_map(|item| item.resolved_path.clone())
            .collect(),
        manifest_hashes: available_manifests
            .iter()
            .filter_map(|item| item.content_hash.clone())
            .collect(),
        lockfile_paths: available_lockfiles
            .iter()
            .filter_map(|item| item.resolved_path.clone())
            .collect(),
        lockfile_hashes: available_lockfiles
            .iter()
            .filter_map(|item| item.content_hash.clone())
            .collect(),
    }
}

// package_intent_parser.py `_local_execution_disables_install`
pub(super) fn local_execution_disables_install(tokens: &[String]) -> bool {
    let name = if tokens.is_empty() {
        String::new()
    } else {
        command_name(&tokens[0])
    };
    let local_only_flags = local_execution_flags(&name);
    for token in &tokens[1..] {
        if !token.starts_with('-') {
            return false;
        }
        if !local_only_flags.contains(&token.as_str()) {
            return false;
        }
        if matches!(token.as_str(), "--no" | "--no-install") {
            return true;
        }
    }
    false
}

// package_intent_parser.py `_local_executable_name`
pub(super) fn local_executable_name(
    tokens: &[String],
    package_name: Option<&str>,
    workspace: Option<&Path>,
    effective_cwd: &Path,
) -> Option<String> {
    let name = if tokens.is_empty() {
        String::new()
    } else {
        command_name(&tokens[0])
    };
    let allowed_flags = local_execution_flags(&name);
    let mut index = 1usize;
    while index < tokens.len() && tokens[index].starts_with('-') {
        if name == "npx" && tokens[index] == "--package" && index + 1 < tokens.len() {
            index += 2;
            continue;
        }
        if name == "npx" && tokens[index].starts_with("--package=") {
            index += 1;
            continue;
        }
        if !allowed_flags.contains(&tokens[index].as_str()) {
            return None;
        }
        index += 1;
    }
    if index >= tokens.len() {
        return None;
    }
    let executable = &tokens[index];
    let executable_re: &Regex = {
        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").expect("exec name"));
        &RE
    };
    if executable_re.is_match(executable) {
        return Some(executable.clone());
    }
    let package_name = package_name?;
    installed_package_bin_name(workspace, effective_cwd, package_name)
}

// package_intent_parser.py `_workspace_js_dependency_version`
pub(super) fn workspace_js_dependency_version(
    workspace: &Path,
    effective_cwd: &Path,
    package_name: &str,
) -> Option<String> {
    let dependency_name = local_executable_package_alias(package_name);
    for root in node_resolution_roots(workspace, effective_cwd) {
        let payload: Value = match std::fs::read_to_string(root.join("package.json"))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
        {
            Some(payload) => payload,
            None => continue,
        };
        let Some(map) = payload.as_object() else {
            continue;
        };
        for key in [
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ] {
            if let Some(dependencies) = map.get(key).and_then(Value::as_object) {
                if let Some(version) = dependencies.get(dependency_name).and_then(Value::as_str) {
                    let version = version.trim();
                    return if version.is_empty() {
                        None
                    } else {
                        Some(version.to_owned())
                    };
                }
            }
        }
    }
    None
}

// package_intent_parser.py `_local_package_execution_evidence`
#[allow(clippy::too_many_arguments)]
pub(super) fn local_package_execution_evidence(
    command: &str,
    tokens: &[String],
    workspace: Option<&Path>,
    effective_path: Option<&str>,
    path_source: &str,
    effective_cwd: Option<&Path>,
    cwd_source: &str,
    execution_context_hash: &str,
    manifest_paths: &[String],
    lockfile_paths: &[String],
) -> LocalPackageExecutionEvidence {
    let package_spec = exec_package_spec(tokens);
    let package_name = package_spec
        .as_deref()
        .and_then(|spec| js_target(spec).package_name);
    let Some(effective_cwd_path) = effective_cwd else {
        return LocalPackageExecutionEvidence {
            manager_name: command.to_owned(),
            path_source: path_source.to_owned(),
            effective_cwd: "<unresolved>".to_owned(),
            cwd_source: cwd_source.to_owned(),
            manager_is_guard_shim: false,
            local_only_requested: local_execution_disables_install(tokens),
            context_hash: execution_context_hash.to_owned(),
            package_name,
            executable_name: None,
            declared_version: None,
            manager: None,
            local_executable: None,
            manifests: Vec::new(),
            lockfiles: Vec::new(),
            typescript_launch: None,
        };
    };
    let executable_name = local_executable_name(
        tokens,
        package_name.as_deref(),
        workspace,
        effective_cwd_path,
    );
    let manager_path = effective_path.and_then(|path| which_on_path(command, path));
    let manager = manager_path
        .as_ref()
        .map(|path| execution_file_evidence(Path::new(path), path));
    let manager_is_guard_shim = manager_evidence_is_guard_shim(command, manager.as_ref());
    let local_executable = match (workspace, executable_name.as_deref()) {
        (Some(workspace), Some(name)) => Some(local_executable_evidence(
            workspace,
            effective_cwd_path,
            name,
        )),
        _ => None,
    };
    let declared_version = match (workspace, package_name.as_deref()) {
        (Some(workspace), Some(name)) => {
            workspace_js_dependency_version(workspace, effective_cwd_path, name)
        }
        _ => None,
    };
    LocalPackageExecutionEvidence {
        manager_name: command.to_owned(),
        path_source: path_source.to_owned(),
        effective_cwd: effective_cwd_path.to_string_lossy().into_owned(),
        cwd_source: cwd_source.to_owned(),
        manager_is_guard_shim,
        local_only_requested: local_execution_disables_install(tokens),
        context_hash: execution_context_hash.to_owned(),
        package_name,
        executable_name,
        declared_version,
        manager,
        local_executable,
        manifests: local_context_file_evidence(
            workspace,
            effective_cwd_path,
            manifest_paths,
            &["package.json".to_owned()],
        ),
        lockfiles: local_context_file_evidence(
            workspace,
            effective_cwd_path,
            lockfile_paths,
            &JS_LOCKFILE_NAMES
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>(),
        ),
        typescript_launch: None,
    }
}
