use super::*;

/// `_resolve_workspace` (:52-77).
pub(super) fn resolve_workspace(workspace: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let resolved = expand_user(workspace).canonicalize().map_err(|error| {
        RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            format!("Restricted pytest workspace could not be resolved: {error}"),
        )
    })?;
    if !resolved.is_dir() {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace must be an existing directory.",
        ));
    }
    if workspace_is_broad_or_sensitive(&resolved) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace cannot be a filesystem, home, temporary, or credential-directory root.",
        ));
    }
    if !PROJECT_WORKSPACE_MARKERS
        .iter()
        .any(|marker| resolved.join(marker).exists())
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace must be an explicit project root with a recognized project marker.",
        ));
    }
    Ok(resolved)
}

/// `_workspace_is_broad_or_sensitive` (:78-104).
pub(super) fn workspace_is_broad_or_sensitive(workspace: &Path) -> bool {
    let broad_roots: HashSet<PathBuf> = [
        "/",
        "/Users",
        "/etc",
        "/home",
        "/private",
        "/private/tmp",
        "/private/var",
        "/tmp",
        "/var",
        "/var/tmp",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    if broad_roots.contains(workspace) {
        return true;
    }
    let home = host_home_directory();
    let home = match home {
        Some(h) => h,
        None => return true,
    };
    if workspace == home || home.ancestors().skip(1).any(|p| p == workspace) {
        return true;
    }
    let relative_to_home = match workspace.strip_prefix(&home) {
        Ok(rel) => rel,
        Err(_) => return false,
    };
    match relative_to_home.components().next() {
        Some(component) => {
            SENSITIVE_HOME_ROOT_NAMES.contains(component.as_os_str().to_string_lossy().as_ref())
        }
        None => false,
    }
}

/// `_resolve_cwd` (:105-121).
#[allow(dead_code)]
pub(super) fn resolve_cwd(cwd: &Path, workspace: &Path) -> Result<PathBuf, RestrictedPytestError> {
    let resolved = expand_user(cwd)
        .canonicalize()
        .ok()
        .filter(|resolved| resolved.strip_prefix(workspace).is_ok())
        .ok_or_else(|| {
            RestrictedPytestError::new(
                PYTEST_INVALID_WORKSPACE_REASON_CODE,
                "Restricted pytest cwd must resolve to an existing directory inside the approved workspace.",
            )
        })?;
    if !resolved.is_dir() {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest cwd must be a directory.",
        ));
    }
    Ok(resolved)
}

/// `_resolve_pytest_executable` (:122-162).
pub(super) fn resolve_pytest_executable(
    command: &[String],
    cwd: &Path,
    workspace: &Path,
    search_path: &str,
) -> Result<(PathBuf, PathBuf), RestrictedPytestError> {
    let command_name = Path::new(&command[0].replace('\\', "/"))
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if PYTEST_EXECUTABLE_NAMES.contains(command_name.as_str()) {
        validate_pytest_args(&command[1..])?;
    } else if regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &command_name) {
        if !python_args_target_pytest(&command[1..]) {
            return Err(RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation.",
            ));
        }
    } else {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest accepts only a pytest executable or a Python `-m pytest` invocation.",
        ));
    }
    let launch_executable = locate_executable(&command[0], cwd, search_path)?;
    let executable = resolve_executable(&command[0], cwd, search_path)?;
    let launched_from_workspace = path_is_within_lexically(&launch_executable, workspace);
    if !launched_from_workspace && !path_is_within_any(&executable, &TRUSTED_EXECUTABLE_ROOTS) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable must be inside the workspace or a trusted system installation root.",
        ));
    }
    if PYTEST_EXECUTABLE_NAMES.contains(command_name.as_str())
        && !PYTEST_EXECUTABLE_NAMES.contains(
            &executable
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default()
                .as_str(),
        )
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable symlink does not resolve to a pytest executable.",
        ));
    }
    if regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &command_name)
        && !regex_is_match(
            &PYTHON_EXECUTABLE_PATTERN,
            &executable
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
        )
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted Python symlink does not resolve to a Python executable.",
        ));
    }
    Ok((launch_executable, executable))
}

/// `_validate_pytest_args` (:163-170).
pub(super) fn validate_pytest_args(args: &[String]) -> Result<(), RestrictedPytestError> {
    if args
        .iter()
        .any(|item| matches!(item.as_str(), ";" | "&&" | "||" | "|" | "|&" | "&"))
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest receives argv directly and does not accept shell control operators.",
        ));
    }
    Ok(())
}

/// `_python_args_target_pytest` (:171-194).
pub(super) fn python_args_target_pytest(args: &[String]) -> bool {
    let mut index = 0usize;
    while index < args.len() {
        let item = &args[index];
        if item == "--" {
            return false;
        }
        if item == "-c"
            || item == "--command"
            || item.starts_with("-c")
            || item.starts_with("--command=")
        {
            return false;
        }
        if item == "-m" {
            return args
                .get(index + 1)
                .map(|next| next.split('.').next() == Some("pytest"))
                .unwrap_or(false);
        }
        if item.starts_with("-m") && item.len() > 2 {
            return item[2..].split('.').next() == Some("pytest");
        }
        if matches!(item.as_str(), "-W" | "-X" | "--check-hash-based-pycs") {
            index += 2;
            continue;
        }
        if item.starts_with("-W")
            || item.starts_with("-X")
            || item.starts_with("--check-hash-based-pycs=")
        {
            index += 1;
            continue;
        }
        if !item.starts_with('-') {
            return false;
        }
        index += 1;
    }
    false
}

/// `_resolve_executable` (:195-218).
pub(super) fn resolve_executable(
    value: &str,
    cwd: &Path,
    search_path: &str,
) -> Result<PathBuf, RestrictedPytestError> {
    let candidate = locate_executable(value, cwd, search_path)?;
    let resolved = candidate.canonicalize().map_err(|_| {
        RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest executable could not be resolved: {value}"),
        )
    })?;
    let metadata = resolved.metadata().map_err(|_| {
        RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest executable could not be inspected: {value}"),
        )
    })?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest target is not an executable regular file: {value}"),
        ));
    }
    Ok(resolved)
}

/// `_locate_executable` (:219-233).
pub(super) fn locate_executable(
    value: &str,
    cwd: &Path,
    search_path: &str,
) -> Result<PathBuf, RestrictedPytestError> {
    let mut candidate = expand_user(Path::new(value));
    if candidate.is_absolute() || value.contains('/') || value.contains('\\') {
        if !candidate.is_absolute() {
            candidate = cwd.join(&candidate);
        }
        return Ok(path_absolute(&candidate));
    }
    match shutil_which(value, Some(search_path)) {
        Some(located) => Ok(path_absolute(&expand_user(&located))),
        None => Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            format!("Restricted pytest executable was not found on PATH: {value}"),
        )),
    }
}

/// `_select_backend` (:234-259).
pub(super) fn select_backend(
    platform: &str,
    backend_executable: Option<&Path>,
    search_path: &str,
) -> Result<(RestrictedPytestBackend, PathBuf), RestrictedPytestError> {
    let (backend, candidate): (RestrictedPytestBackend, PathBuf) = if platform == "darwin" {
        (
            "macos-seatbelt",
            backend_executable
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("/usr/bin/sandbox-exec")),
        )
    } else if platform.starts_with("linux") {
        let located = shutil_which("bwrap", Some(search_path));
        (
            "linux-bubblewrap",
            backend_executable
                .map(|p| p.to_path_buf())
                .or(located)
                .unwrap_or_else(|| PathBuf::from("/usr/bin/bwrap")),
        )
    } else {
        return Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            "No enforceable restricted pytest backend is available for this platform; execution was not started.",
        ));
    };
    match trusted_backend_executable(&candidate) {
        Some(trusted) => Ok((backend, trusted)),
        None => Err(RestrictedPytestError::new(
            PYTEST_SANDBOX_UNAVAILABLE_REASON_CODE,
            format!(
                "Required {backend} backend is missing or not a trusted system executable; execution was not started."
            ),
        )),
    }
}

/// `_trusted_backend_executable` (:260-276).
pub(super) fn trusted_backend_executable(candidate: &Path) -> Option<PathBuf> {
    let resolved = expand_user(candidate).canonicalize().ok()?;
    let metadata = resolved.metadata().ok()?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return None;
    }
    if metadata.mode() & 0o022 != 0 {
        return None;
    }
    if metadata.uid() != 0 {
        return None;
    }
    if !path_is_within_any(
        &resolved,
        &[
            PathBuf::from("/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/local/bin"),
        ],
    ) {
        return None;
    }
    Some(resolved)
}
