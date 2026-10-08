use super::*;

/// `shutil.which(command, path=...)` — search `command` in a `:`-separated path.
pub(super) fn which_on_path(command: &str, path: &str) -> Option<String> {
    if command.contains('/') {
        let candidate = Path::new(command);
        if is_executable(candidate) {
            return Some(command.to_owned());
        }
        return None;
    }
    for entry in path.split(':') {
        if entry.is_empty() {
            continue;
        }
        let candidate = Path::new(entry).join(command);
        if is_executable(&candidate) {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

pub(super) fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

// package_intent_parser.py `_manager_evidence_is_guard_shim`
pub(super) fn manager_evidence_is_guard_shim(
    command: &str,
    manager: Option<&PackageExecutionFileEvidence>,
) -> bool {
    let Some(manager) = manager else {
        return false;
    };
    let Some(resolved_path) = &manager.resolved_path else {
        return false;
    };
    let home = match std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        Some(home) => PathBuf::from(home),
        None => return false,
    };
    let expected_shim = home
        .join(".hol-guard")
        .join("package-shims")
        .join("bin")
        .join(command)
        .canonicalize();
    match expected_shim {
        Ok(expected) => Path::new(resolved_path) == expected,
        Err(_) => false,
    }
}

// package_intent_parser.py `_local_executable_evidence`
pub(super) fn local_executable_evidence(
    workspace: &Path,
    effective_cwd: &Path,
    executable_name: &str,
) -> PackageExecutionFileEvidence {
    let suffixes: &[&str] = if cfg!(windows) {
        &["", ".cmd", ".ps1"]
    } else {
        &[""]
    };
    for root in node_resolution_roots(workspace, effective_cwd) {
        let executable_dir = root.join("node_modules").join(".bin");
        for suffix in suffixes {
            let candidate = executable_dir.join(format!("{executable_name}{suffix}"));
            if candidate.symlink_metadata().is_ok() {
                return execution_file_evidence(
                    &candidate,
                    &execution_display_path(workspace, &candidate),
                );
            }
        }
    }
    let expected = effective_cwd
        .join("node_modules")
        .join(".bin")
        .join(executable_name);
    PackageExecutionFileEvidence {
        path: execution_display_path(workspace, &expected),
        resolved_path: None,
        status: "missing",
        file_identity: None,
        content_hash: None,
    }
}

// package_intent_parser.py `_installed_package_bin_name`
pub(super) fn installed_package_bin_name(
    workspace: Option<&Path>,
    effective_cwd: &Path,
    package_name: &str,
) -> Option<String> {
    let workspace = workspace?;
    for root in node_resolution_roots(workspace, effective_cwd) {
        let manifest = package_name
            .split('/')
            .fold(root.join("node_modules"), |acc, part| acc.join(part))
            .join("package.json");
        let payload: Value = match std::fs::read_to_string(&manifest)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
        {
            Some(payload) => payload,
            None => continue,
        };
        let Some(map) = payload.as_object() else {
            continue;
        };
        let bin_value = map.get("bin");
        let fallback = package_name.rsplit('/').next().unwrap_or(package_name);
        if let Some(bin_str) = bin_value.and_then(Value::as_str) {
            if !bin_str.trim().is_empty() {
                return Some(fallback.to_owned());
            }
        }
        if let Some(bin_map) = bin_value.and_then(Value::as_object) {
            let names: Vec<String> = bin_map
                .iter()
                .filter(|(_, value)| {
                    value
                        .as_str()
                        .map(|s| !s.trim().is_empty())
                        .unwrap_or(false)
                })
                .map(|(name, _)| name.clone())
                .collect();
            if names.iter().any(|name| name == fallback) {
                return Some(fallback.to_owned());
            }
            if names.len() == 1 {
                return Some(names[0].clone());
            }
        }
    }
    let fallback = package_name.rsplit('/').next().unwrap_or(package_name);
    let re: &Regex = {
        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").expect("bin name"));
        &RE
    };
    if re.is_match(fallback) {
        Some(fallback.to_owned())
    } else {
        None
    }
}

// package_intent_parser.py `_node_resolution_roots`
pub(super) fn node_resolution_roots(workspace: &Path, effective_cwd: &Path) -> Vec<PathBuf> {
    let workspace_root = expand_resolve(workspace);
    let mut current = expand_resolve(effective_cwd);
    let boundary = if current == workspace_root
        || current
            .ancestors()
            .any(|ancestor| ancestor == workspace_root)
    {
        workspace_root.clone()
    } else {
        PathBuf::from(
            current
                .components()
                .next()
                .map(|c| c.as_os_str())
                .unwrap_or_default(),
        )
    };
    let mut roots: Vec<PathBuf> = Vec::new();
    loop {
        roots.push(current.clone());
        if current == boundary {
            break;
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => break,
        }
    }
    roots
}

// package_intent_parser.py `_local_context_file_evidence`
pub(super) fn local_context_file_evidence(
    workspace: Option<&Path>,
    effective_cwd: &Path,
    declared_paths: &[String],
    candidate_names: &[String],
) -> Vec<PackageExecutionFileEvidence> {
    let Some(workspace) = workspace else {
        return Vec::new();
    };
    let mut candidates: Vec<(PathBuf, String)> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for relative_path in declared_paths {
        let candidate = effective_cwd.join(relative_path);
        let normalized = absolute(&candidate);
        if seen.insert(normalized) {
            candidates.push((
                candidate.clone(),
                execution_display_path(workspace, &candidate),
            ));
        }
    }
    for root in node_resolution_roots(workspace, effective_cwd) {
        for name in candidate_names {
            let candidate = root.join(name);
            let normalized = absolute(&candidate);
            if seen.contains(&normalized) || candidate.symlink_metadata().is_err() {
                continue;
            }
            seen.insert(normalized);
            candidates.push((
                candidate.clone(),
                execution_display_path(workspace, &candidate),
            ));
        }
    }
    candidates
        .iter()
        .map(|(candidate, display)| execution_file_evidence(candidate, display))
        .collect()
}

pub(super) fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

// package_intent_parser.py `_execution_file_evidence`
pub(super) fn execution_file_evidence(
    path: &Path,
    display_path: &str,
) -> PackageExecutionFileEvidence {
    let resolved = match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: None,
                status: "missing",
                file_identity: None,
                content_hash: None,
            };
        }
    };
    // Python opens the resolved path with O_RDONLY|O_CLOEXEC|O_NOFOLLOW and
    // fstats+reads. Rust: open then metadata + read, treating symlink targets
    // as resolved already. `canonicalize` resolves symlinks so O_NOFOLLOW is
    // implicitly satisfied.
    let file = match std::fs::File::open(&resolved) {
        Ok(file) => file,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: Some(resolved.to_string_lossy().into_owned()),
                status: "unreadable",
                file_identity: path_identity(&resolved),
                content_hash: None,
            };
        }
    };
    let before = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: Some(resolved.to_string_lossy().into_owned()),
                status: "unreadable",
                file_identity: None,
                content_hash: None,
            };
        }
    };
    if !before.is_file() {
        return PackageExecutionFileEvidence {
            path: display_path.to_owned(),
            resolved_path: Some(resolved.to_string_lossy().into_owned()),
            status: "not_regular",
            file_identity: Some(stat_identity(&before)),
            content_hash: None,
        };
    }
    let mut file = file;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => digest.update(&buffer[..n]),
            Err(_) => {
                return PackageExecutionFileEvidence {
                    path: display_path.to_owned(),
                    resolved_path: Some(resolved.to_string_lossy().into_owned()),
                    status: "unreadable",
                    file_identity: None,
                    content_hash: None,
                };
            }
        }
    }
    let after = match file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => {
            return PackageExecutionFileEvidence {
                path: display_path.to_owned(),
                resolved_path: Some(resolved.to_string_lossy().into_owned()),
                status: "unreadable",
                file_identity: None,
                content_hash: None,
            };
        }
    };
    let identity_before = stat_identity(&before);
    let identity_after = stat_identity(&after);
    if identity_before != identity_after {
        return PackageExecutionFileEvidence {
            path: display_path.to_owned(),
            resolved_path: Some(resolved.to_string_lossy().into_owned()),
            status: "unstable",
            file_identity: Some(identity_after),
            content_hash: None,
        };
    }
    PackageExecutionFileEvidence {
        path: display_path.to_owned(),
        resolved_path: Some(resolved.to_string_lossy().into_owned()),
        status: "available",
        file_identity: Some(identity_after),
        content_hash: Some(format!("sha256:{}", hex::encode(digest.finalize()))),
    }
}

// package_intent_parser.py `_split_shell_tokens`
// `shlex` with `punctuation_chars=";&|"`, `whitespace_split=True`, `commenters=""`.
#[allow(dead_code)]
pub(super) fn split_shell_tokens_local(command_text: &str) -> Vec<String> {
    split_shell_tokens(command_text).unwrap_or_default()
}

/// `os.defpath` equivalent — POSIX standard PATH fallback.
pub(super) fn default_path() -> String {
    "/bin:/usr/bin".to_owned()
}
