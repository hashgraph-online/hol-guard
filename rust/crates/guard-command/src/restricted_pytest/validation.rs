use super::*;

pub(super) fn resolve_workspace_with_home(
    workspace: &Path,
    home: Option<&Path>,
) -> Result<PathBuf, RestrictedPytestError> {
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
    let sensitive = match home {
        Some(home) => workspace_is_broad_or_sensitive_for_home(&resolved, Some(home)),
        None => workspace_is_broad_or_sensitive(&resolved),
    };
    if sensitive {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace cannot be a filesystem, home, temporary, or credential-directory root.",
        ));
    }
    if !PROJECT_WORKSPACE_MARKERS
        .iter()
        .any(|marker| resolved.join(marker).exists())
        && !holds_root_test_module(&resolved)
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_WORKSPACE_REASON_CODE,
            "Restricted pytest workspace must be an explicit project root with a recognized project marker.",
        ));
    }
    Ok(resolved)
}

/// pytest treats a directory holding `conftest.py` or a `test_*.py` module as
/// its root when no configuration file exists, so a fresh project with only
/// source and tests still counts. The broad and sensitive roots are refused
/// before this runs. Only regular files count, and the scan stops early.
fn holds_root_test_module(workspace: &Path) -> bool {
    let Ok(entries) = fs::read_dir(workspace) else {
        return false;
    };
    entries.take(512).flatten().any(|entry| {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return false;
        };
        let test_module = name == "conftest.py"
            || name.strip_suffix(".py").is_some_and(|stem| {
                stem.len() > 5 && (stem.starts_with("test_") || stem.ends_with("_test"))
            });
        test_module && entry.file_type().is_ok_and(|kind| kind.is_file())
    })
}

/// `_workspace_is_broad_or_sensitive` (:78-104).
pub(super) fn workspace_is_broad_or_sensitive(workspace: &Path) -> bool {
    workspace_is_broad_or_sensitive_for_home(workspace, None)
}

pub(super) fn workspace_is_broad_or_sensitive_for_home(
    workspace: &Path,
    home: Option<&Path>,
) -> bool {
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
    // The caller home is an extra root. It must not replace the account home
    // from the password database, or a different `$HOME` would hide that root.
    let mut homes = Vec::new();
    if let Some(host) = host_home_directory() {
        homes.push(host);
    }
    if let Some(path) = home {
        let caller = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if !homes.iter().any(|existing| existing == &caller) {
            homes.push(caller);
        }
    }
    if homes.is_empty() {
        return true;
    }
    homes
        .iter()
        .any(|home| sensitive_under_home(workspace, home))
}

fn sensitive_under_home(workspace: &Path, home: &Path) -> bool {
    if workspace == home
        || home
            .ancestors()
            .skip(1)
            .any(|ancestor| ancestor == workspace)
    {
        return true;
    }
    let Ok(relative) = workspace.strip_prefix(home) else {
        return false;
    };
    match relative.components().next() {
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
    if !launched_from_workspace
        && !path_is_within_any(&executable, &TRUSTED_EXECUTABLE_ROOTS)
        // `resolve_executable` answers the `/usr/bin` shim here, so the path
        // under test is inside the developer directory rather than under a
        // trusted root. `allowed_executable_path` already accepts it on the
        // same terms; without the same exemption `python3 -m pytest` fails at
        // plan time on exactly the hosts the shim resolution is for.
        && !super::developer_shim::is_developer_tool(&executable)
        && venv::external_root(&launch_executable, &executable, workspace).is_none()
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Contained executable must be inside the workspace, a trusted system installation root, or a virtual environment of a trusted Python runtime.",
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
    // macOS ships `/usr/bin/python3` and its siblings as shims that ask
    // `xcode-select` where the real tool is. That lookup cannot run inside
    // containment, so it is answered here instead and the run execs the tool
    // the shim would have forwarded to.
    let resolved = super::developer_shim::forwarded_tool(&resolved).unwrap_or(resolved);
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
