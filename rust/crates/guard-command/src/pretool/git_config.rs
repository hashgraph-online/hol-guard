use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CONFIG_LIMIT: u64 = 65_536;

pub(super) fn execution_free(
    executable: &str,
    arguments: &[String],
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let remaining = crate::command_compatibility::git_inspection_arguments(arguments, context)?;
    let operation = remaining.first()?.as_str();
    if !matches!(operation, "status" | "diff" | "log" | "show") {
        return None;
    }
    Some(
        probe(
            executable,
            arguments,
            remaining,
            operation,
            context,
            deadline,
            execution_environment,
        )
        .unwrap_or(false),
    )
}

#[allow(clippy::too_many_arguments)]
fn probe(
    executable: &str,
    arguments: &[String],
    remaining: &[String],
    operation: &str,
    context: super::PathContext<'_>,
    deadline: Option<Instant>,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    let deadline = deadline
        .unwrap_or_else(|| Instant::now() + Duration::from_millis(250))
        .min(Instant::now() + Duration::from_millis(250));
    if Instant::now() >= deadline {
        return None;
    }
    let home = fs::canonicalize(context.0?).ok()?;
    let cwd = fs::canonicalize(context.1?).ok()?;
    let leading = &arguments[..arguments.len().checked_sub(remaining.len())?];
    if !home.is_dir() || !cwd.is_dir() || !clean_environment(execution_environment) {
        return None;
    }
    let binary = trusted_git(executable, &home, &cwd, execution_environment)?;
    let mut command = Command::new(binary);
    command.env_clear();
    #[cfg(windows)]
    for key in ["SYSTEMROOT", "WINDIR"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    if let Some(directory) =
        execution_environment.and_then(|context| context.xdg_config_home.as_deref())
    {
        command.env("XDG_CONFIG_HOME", directory);
    } else if execution_environment.is_none() {
        if let Some(directory) = std::env::var_os("XDG_CONFIG_HOME") {
            command.env("XDG_CONFIG_HOME", directory);
        }
    }
    if execution_environment.is_some_and(|context| context.git_config_no_system) {
        command.env("GIT_CONFIG_NOSYSTEM", "1");
    }
    let git_home = execution_environment
        .and_then(|context| context.home.as_deref())
        .map(Path::new)
        .unwrap_or(&home);
    let mut child = command
        .args(leading)
        .args([
            "--no-pager",
            "config",
            "--null",
            "--get-regexp",
            "^(core\\.fsmonitor|core\\.pager|pager\\..*|diff\\.external|diff\\..*\\.(command|textconv)|filter\\..*\\.(process|clean|smudge)|log\\.showsignature|gpg\\.program|gpg\\..*\\.program)$",
        ])
        .current_dir(&cwd)
        .env("HOME", git_home)
        .env("USERPROFILE", git_home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take(CONFIG_LIMIT + 1)
            .read_to_end(&mut output)
            .ok()?;
        (output.len() <= CONFIG_LIMIT as usize).then_some(output)
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = reader.join().ok()??;
    let status = status?;
    if !(status.success() || status.code() == Some(1) && output.is_empty()) {
        return None;
    }
    let output = std::str::from_utf8(&output).ok()?;
    let options = remaining
        .iter()
        .skip(1)
        .take_while(|value| value.as_str() != "--");
    if options
        .clone()
        .any(|value| value.as_str() == "--show-signature")
    {
        return Some(false);
    }
    let no_external = options
        .clone()
        .filter_map(|value| match value.as_str() {
            "--no-ext-diff" => Some(true),
            "--ext-diff" => Some(false),
            _ => None,
        })
        .last()
        == Some(true);
    let no_textconv = options
        .clone()
        .filter_map(|value| match value.as_str() {
            "--no-textconv" => Some(true),
            "--textconv" => Some(false),
            _ => None,
        })
        .last()
        == Some(true);
    let mut effective = std::collections::BTreeMap::new();
    for record in output.split('\0').filter(|record| !record.is_empty()) {
        let (key, value) = record.split_once('\n')?;
        effective.insert(key, value);
    }
    let pager_key = format!("pager.{operation}");
    let pager_setting = effective.get(pager_key.as_str()).copied();
    let configured_pager = pager_setting.or_else(|| {
        (operation != "status")
            .then(|| effective.get("core.pager").copied())
            .flatten()
    });
    let environment_pager = environment_pager_disabled(execution_environment);
    let git_pager_disabled = git_pager_disabled(execution_environment);
    let no_pager = leading
        .iter()
        .any(|argument| matches!(argument.as_str(), "-P" | "--no-pager"));
    let configured_paging = !no_pager
        && configured_pager.map_or(operation != "status", |value| !disabled_boolean(value));
    let configured_pager_is_cat = configured_pager.is_some_and(|value| value == "cat");
    let paging = configured_paging
        && !configured_pager_is_cat
        && !environment_pager.is_some_and(|disabled| disabled);
    if paging && environment_pager == Some(false) {
        return Some(false);
    }
    for (key, value) in effective {
        let disabled = disabled_boolean(value);
        let unsafe_value = match key {
            "core.fsmonitor" => matches!(operation, "status" | "diff") && !disabled,
            "core.pager" => {
                configured_paging
                    && !git_pager_disabled
                    && pager_setting.is_none_or(enabled_boolean)
                    && !value.is_empty()
                    && value != "cat"
            }
            key if key.starts_with("pager.") => {
                key == pager_key
                    && !git_pager_disabled
                    && !disabled
                    && !value.is_empty()
                    && value != "cat"
                    && if enabled_boolean(value) {
                        paging
                    } else {
                        configured_paging
                    }
            }
            "diff.external" => !no_external && !value.is_empty(),
            key if key.starts_with("diff.") && key.ends_with(".command") => {
                !no_external && !value.is_empty()
            }
            key if key.starts_with("diff.") && key.ends_with(".textconv") => {
                !no_textconv && !value.is_empty()
            }
            key if key.starts_with("filter.") => {
                matches!(operation, "status" | "diff") && !value.is_empty()
            }
            "log.showsignature" => matches!(operation, "log" | "show") && !disabled,
            key if key.starts_with("gpg.") => {
                matches!(operation, "log" | "show") && !value.is_empty()
            }
            _ => return None,
        };
        if unsafe_value {
            return Some(false);
        }
    }
    Some(true)
}

fn disabled_boolean(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "0" | "false" | "no" | "off"
    )
}

fn enabled_boolean(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "on" | "1"
    )
}

fn environment_pager_disabled(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<bool> {
    match execution_environment {
        Some(context) => {
            if context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_PAGER"))
            {
                Some(context.git_pager_disabled)
            } else if context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("PAGER"))
            {
                Some(context.pager_disabled)
            } else {
                None
            }
        }
        None => std::env::var_os("GIT_PAGER")
            .map(|value| value.is_empty() || value.to_string_lossy() == "cat")
            .or_else(|| {
                std::env::var_os("PAGER")
                    .map(|value| value.is_empty() || value.to_string_lossy() == "cat")
            }),
    }
}

fn git_pager_disabled(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    match execution_environment {
        Some(context) => {
            context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_PAGER"))
                && context.git_pager_disabled
        }
        None => std::env::var_os("GIT_PAGER")
            .is_some_and(|value| value.is_empty() || value.to_string_lossy() == "cat"),
    }
}

fn clean_environment(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> bool {
    let names = match execution_environment {
        Some(context) => {
            let declares_xdg = context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("XDG_CONFIG_HOME"));
            if declares_xdg != context.xdg_config_home.is_some() {
                return false;
            }
            let declares_no_system = context
                .environment_names
                .iter()
                .any(|name| name.eq_ignore_ascii_case("GIT_CONFIG_NOSYSTEM"));
            if declares_no_system != context.git_config_no_system {
                return false;
            }
            if context.path.len() > 32768
                || context.path.contains('\0')
                || context
                    .home
                    .as_ref()
                    .is_some_and(|path| path.len() > 32768 || path.contains('\0'))
                || context
                    .xdg_config_home
                    .as_ref()
                    .is_some_and(|path| path.len() > 32768 || path.contains('\0'))
                || context.environment_names.len() > 512
                || context.environment_digest.len() != 64
                || !context
                    .environment_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                || context
                    .environment_names
                    .iter()
                    .any(|name| name.len() > 256 || name.chars().any(char::is_control))
            {
                return false;
            }
            context.environment_names.clone()
        }
        None => std::env::vars_os()
            .filter(|(_, value)| !value.is_empty())
            .map(|(name, _)| name.to_string_lossy().into_owned())
            .collect(),
    };
    !names.iter().any(|key| {
        let key = key.to_ascii_uppercase();
        key.starts_with("GIT_TRACE")
            || key.starts_with("DYLD_")
            || key.starts_with("LD_")
            || (key.starts_with("GIT_CONFIG")
                && !(key == "GIT_CONFIG_NOSYSTEM"
                    && execution_environment.is_some_and(|context| context.git_config_no_system)))
            || matches!(
                key.as_str(),
                "GIT_DIR"
                    | "GIT_EXTERNAL_DIFF"
                    | "GIT_COMMON_DIR"
                    | "GIT_WORK_TREE"
                    | "GIT_EXEC_PATH"
                    | "GIT_DISCOVERY_ACROSS_FILESYSTEM"
                    | "LD_PRELOAD"
                    | "LD_LIBRARY_PATH"
                    | "DYLD_INSERT_LIBRARIES"
                    | "DYLD_LIBRARY_PATH"
            )
    })
}

fn trusted_git(
    executable: &str,
    home: &Path,
    cwd: &Path,
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
) -> Option<PathBuf> {
    let supplied = Path::new(executable);
    let path = if supplied.components().count() > 1 {
        fs::canonicalize(if supplied.is_absolute() {
            supplied.to_path_buf()
        } else {
            cwd.join(supplied)
        })
        .ok()?
    } else {
        let mut found = None;
        let path = execution_environment
            .map(|context| std::ffi::OsString::from(&context.path))
            .or_else(|| std::env::var_os("PATH"))?;
        for directory in std::env::split_paths(&path) {
            let directory = if directory.is_absolute() {
                directory
            } else {
                cwd.join(directory)
            };
            let candidate = directory.join(if cfg!(windows) { "git.exe" } else { "git" });
            if candidate.is_file() {
                found = Some(fs::canonicalize(candidate).ok()?);
                break;
            }
        }
        found?
    };
    if path.starts_with(home)
        || path.starts_with(cwd)
        || path.starts_with(std::env::temp_dir())
        || path.starts_with("/tmp")
        || path.starts_with("/private/tmp")
    {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let home_metadata = fs::metadata(home).ok()?;
        let owner = home_metadata.uid();
        for ancestor in std::iter::once(path.as_path()).chain(path.ancestors().skip(1)) {
            let metadata = fs::metadata(ancestor).ok()?;
            if metadata.mode() & 0o002 != 0
                || (metadata.mode() & 0o020 != 0
                    && metadata.uid() != owner
                    && metadata.gid() != home_metadata.gid())
                || !matches!(metadata.uid(), uid if uid == 0 || uid == owner)
            {
                return None;
            }
        }
    }
    #[cfg(windows)]
    {
        if !["ProgramFiles", "ProgramFiles(x86)", "SystemRoot"]
            .iter()
            .filter_map(std::env::var_os)
            .any(|root| path.starts_with(root))
        {
            return None;
        }
    }
    Some(path)
}
