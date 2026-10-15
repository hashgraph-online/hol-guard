use super::*;

pub(super) fn allowed_executables(
    executable: &Path,
    launch_executable: &Path,
    command: &[String],
    cwd: &Path,
    workspace: &Path,
    search_path: &str,
) -> Result<Vec<PathBuf>, RestrictedPytestError> {
    let mut allowed = vec![launch_executable.to_path_buf(), executable.to_path_buf()];
    let command_name = Path::new(&command[0].replace('\\', "/"))
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if PYTEST_EXECUTABLE_NAMES.contains(command_name.as_str()) {
        let interpreter = script_interpreter(executable, cwd, search_path)?;
        if let Some(interpreter) = interpreter {
            let last_name = interpreter
                .last()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &last_name) {
                return Err(RestrictedPytestError::new(
                    PYTEST_INVALID_COMMAND_REASON_CODE,
                    "Restricted pytest entry points must use a Python interpreter.",
                ));
            }
            allowed.extend(interpreter);
        }
    }
    for allowed_executable in allowed.clone() {
        allowed.extend(framework_python_helpers(&allowed_executable));
    }
    let workspace_launcher = path_is_within_lexically(launch_executable, workspace);
    let venv_root = if workspace_launcher {
        None
    } else {
        venv::external_root(launch_executable, executable, workspace)
    };
    let venv_root = venv_root.as_deref();
    if allowed.iter().any(|path| {
        !allowed_executable_path(path, workspace, workspace_launcher || venv_root.is_some())
            && !venv_root.is_some_and(|root| venv::in_bin(path, root))
    }) {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Contained executable resolves to an interpreter outside the workspace and trusted runtime roots.",
        ));
    }
    if allowed
        .iter()
        .any(|path| !executable_symlink_chain_is_approved(path, workspace, venv_root))
    {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Contained executable has an unapproved path in its interpreter symlink chain.",
        ));
    }
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for path in allowed {
        if seen.insert(path.clone()) {
            deduped.push(path);
        }
    }
    Ok(deduped)
}

/// `_framework_python_helpers` (:314-329).
pub(super) fn framework_python_helpers(executable: &Path) -> Vec<PathBuf> {
    if executable
        .parent()
        .and_then(|p| p.file_name())
        .map(|n| n != "bin")
        .unwrap_or(true)
    {
        return Vec::new();
    }
    let version_root = match executable.parent().and_then(|p| p.parent()) {
        Some(root) => root,
        None => return Vec::new(),
    };
    let versions_dir = match version_root.parent() {
        Some(parent) => parent,
        None => return Vec::new(),
    };
    let framework_dir = match versions_dir.parent() {
        Some(parent) => parent,
        None => return Vec::new(),
    };
    if versions_dir
        .file_name()
        .map(|n| n != "Versions")
        .unwrap_or(true)
        || framework_dir
            .file_name()
            .map(|n| n != "Python.framework")
            .unwrap_or(true)
    {
        return Vec::new();
    }
    let helper = version_root
        .join("Resources")
        .join("Python.app")
        .join("Contents")
        .join("MacOS")
        .join("Python");
    if !helper.exists() {
        return Vec::new();
    }
    let resolved = match resolve_executable(
        &helper.to_string_lossy(),
        helper.parent().unwrap_or_else(|| Path::new("/")),
        "",
    ) {
        Ok(resolved) => resolved,
        Err(_) => return Vec::new(),
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in [path_absolute(&helper), resolved] {
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

/// `_allowed_executable_path` (:330-340).
pub(super) fn allowed_executable_path(
    path: &Path,
    workspace: &Path,
    workspace_launcher: bool,
) -> bool {
    if path_is_within_lexically(path, workspace)
        || path_is_within_any(path, &TRUSTED_EXECUTABLE_ROOTS)
    {
        return true;
    }
    let basename = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    workspace_launcher
        && regex_is_match(&PYTHON_EXECUTABLE_PATTERN, &basename)
        && approved_user_python_runtime(path)
}

/// `_approved_user_python_runtime` (:341-369).
pub(super) fn approved_user_python_runtime(path: &Path) -> bool {
    let home = match host_home_directory() {
        Some(home) => home,
        None => return false,
    };
    let absolute = path_absolute(path);
    let relative = match absolute.strip_prefix(&home) {
        Ok(rel) => rel,
        Err(_) => return false,
    };
    let relative_parts: Vec<String> = relative
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let managed_prefixes: &[&[&str]] = &[
        &[".asdf", "installs", "python"],
        &[".local", "share", "mise", "installs", "python"],
        &[".local", "share", "uv", "python"],
        &[".pyenv", "versions"],
        &["Library", "Application Support", "uv", "python"],
        &["Library", "Caches", "uv", "python"],
    ];
    if managed_prefixes.iter().any(|prefix| {
        relative_parts.len() > prefix.len()
            && relative_parts[..prefix.len()]
                .iter()
                .map(|s| s.as_str())
                .eq(prefix.iter().copied())
    }) {
        return true;
    }
    !relative_parts.is_empty()
        && matches!(
            relative_parts[0].as_str(),
            "anaconda3" | "mambaforge" | "miniconda3" | "miniforge3"
        )
        && relative_parts.len() > 2
}

/// `_executable_symlink_chain_is_approved` (:370-385).
/// Links inside an approved external venv's `bin` are part of its launcher.
pub(super) fn executable_symlink_chain_is_approved(
    path: &Path,
    workspace: &Path,
    venv_root: Option<&Path>,
) -> bool {
    let mut current = path_absolute(path);
    for _depth in 0..16 {
        let expansion = match first_symlink_expansion(&current) {
            Some(expansion) => expansion,
            None => return true,
        };
        current = expansion;
        if !path_is_within_lexically(&current, workspace)
            && !path_is_within_any_lexically(&current, &TRUSTED_EXECUTABLE_ROOTS)
            && !approved_user_python_runtime(&current)
            && !venv_root.is_some_and(|root| venv::in_bin(&current, root))
        {
            return false;
        }
    }
    first_symlink_expansion(&current).is_none()
}

/// `_script_interpreter` (:386-415).
pub(super) fn script_interpreter(
    executable: &Path,
    cwd: &Path,
    search_path: &str,
) -> Result<Option<Vec<PathBuf>>, RestrictedPytestError> {
    let first_line = {
        let handle = match fs::File::open(executable) {
            Ok(handle) => handle,
            Err(_) => return Ok(None),
        };
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(handle.take(4096));
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(_) => line,
            Err(_) => return Ok(None),
        }
    };
    if !first_line.starts_with(b"#!") {
        return Ok(None);
    }
    let shebang = match std::str::from_utf8(&first_line[2..]) {
        Ok(text) => text.trim().to_owned(),
        Err(_) => {
            return Err(RestrictedPytestError::new(
                PYTEST_INVALID_COMMAND_REASON_CODE,
                "Restricted pytest executable has an invalid interpreter declaration.",
            ))
        }
    };
    let parts = shlex_split(&shebang).ok_or_else(|| {
        RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an invalid interpreter declaration.",
        )
    })?;
    if parts.is_empty() {
        return Err(RestrictedPytestError::new(
            PYTEST_INVALID_COMMAND_REASON_CODE,
            "Restricted pytest executable has an empty interpreter declaration.",
        ));
    }
    let interpreter_launch = locate_executable(&parts[0], cwd, search_path)?;
    let interpreter = resolve_executable(&parts[0], cwd, search_path)?;
    let mut interpreters = vec![interpreter_launch, interpreter.clone()];
    if interpreter == Path::new("/usr/bin/env") && parts.len() >= 2 {
        let last = parts.last().cloned().unwrap_or_default();
        let target_launch = locate_executable(&last, cwd, search_path)?;
        interpreters.push(target_launch);
        interpreters.push(resolve_executable(&last, cwd, search_path)?);
    }
    Ok(Some(interpreters))
}

/// `shlex.split` (POSIX): single/double quotes, backslash escapes, comment
/// char disabled (shebangs never reach `#` quoting context).
pub(super) fn shlex_split(input: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut state = 0u8; // 0 = unquoted, 1 = single, 2 = double, 3 = escaped
    let mut in_token = false;
    while let Some(ch) = chars.next() {
        match state {
            0 => match ch {
                ' ' | '\t' | '\r' | '\n' => {
                    if in_token {
                        tokens.push(std::mem::take(&mut current));
                        in_token = false;
                    }
                }
                '\'' => {
                    state = 1;
                    in_token = true;
                }
                '"' => {
                    state = 2;
                    in_token = true;
                }
                '\\' => {
                    state = 3;
                    in_token = true;
                }
                _ => {
                    current.push(ch);
                    in_token = true;
                }
            },
            1 => {
                if ch == '\'' {
                    state = 0;
                } else {
                    current.push(ch);
                }
            }
            2 => {
                if ch == '"' {
                    state = 0;
                } else if ch == '\\'
                    && matches!(chars.peek(), Some('"') | Some('\\') | Some('$') | Some('`'))
                {
                    current.push(chars.next().unwrap());
                } else {
                    current.push(ch);
                }
            }
            3 => {
                if ch == '\n' {
                    // escaped newline: line continuation
                } else {
                    current.push(ch);
                }
                state = 0;
            }
            _ => unreachable!(),
        }
    }
    if state == 1 || state == 2 {
        return None; // unclosed quote -> ValueError
    }
    if state == 3 {
        current.push('\\');
    }
    if in_token {
        tokens.push(current);
    }
    Some(tokens)
}
