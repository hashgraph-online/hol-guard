//! Whether the environment and the executable a Git read would use are the
//! ones this host trusts, kept apart from the configuration screens so each
//! file answers one question.

use std::fs;
use std::path::{Path, PathBuf};

pub(in crate::pretool) fn clean_environment(
    execution_environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    home: &Path,
    cwd: &Path,
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
            if !context.has_valid_shape()
                || context
                    .library_search_paths
                    .keys()
                    .any(|name| !context.environment_names.contains(name))
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
    !names.iter().any(|name| {
        // Unix loader search paths are inert on Windows. Elsewhere a search
        // path the hook stamped is checked entry by entry; every other loader
        // variable, including injection, stays a refusal.
        if crate::pretool::trusted_location::inert_loader_search_path(name, cfg!(windows))
            || execution_environment.is_some_and(|context| {
                context.library_search_paths.get(name).is_some_and(|value| {
                    crate::pretool::trusted_location::trusted_library_search_path(value, home, cwd)
                })
            })
        {
            return false;
        }
        let key = name.to_ascii_uppercase();
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
                    | "GIT_INDEX_FILE"
                    | "GIT_OBJECT_DIRECTORY"
                    | "GIT_ALTERNATE_OBJECT_DIRECTORIES"
                    | "GIT_NAMESPACE"
                    | "GIT_REPLACE_REF_BASE"
                    | "GIT_SHALLOW_FILE"
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

pub(in crate::pretool) fn trusted_command(
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
            let command_name = if cfg!(windows) && supplied.extension().is_none() {
                format!("{executable}.exe")
            } else {
                executable.to_owned()
            };
            let candidate = directory.join(command_name);
            if candidate.is_file() {
                found = Some(fs::canonicalize(candidate).ok()?);
                break;
            }
        }
        found?
    };
    let shim = crate::pretool::git_session_probe::apple_developer_tools::selection_overridden(
        &path,
        execution_environment,
    );
    (!shim && crate::pretool::trusted_location::trusted_location(&path, home, cwd)).then_some(path)
}
