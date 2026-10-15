//! Execution-environment and executable trust for Actions reads
//! (`github_actions_read_workflow.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::PyPath;
use crate::sfrs_gh_pyshim::{gettempdir, is_executable, resolve_existing};

const EXECUTION_ROUTING_ENVIRONMENT: &[&str] = &[
    "BASH_ENV",
    "CURL_CA_BUNDLE",
    "ENV",
    "GH_CONFIG_DIR",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "ALL_PROXY",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "ZDOTDIR",
    "all_proxy",
    "https_proxy",
    "http_proxy",
];

const LOADER_PATH_ENVIRONMENT: &[&str] = &[
    "DYLD_FALLBACK_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
];

const PATH_SEPARATOR: char = if cfg!(windows) { ';' } else { ':' };
const DEFAULT_PATH: &str = if cfg!(windows) {
    ".;C:\\bin"
} else {
    "/bin:/usr/bin"
};

/// `shell_read_execution_environment_is_safe`.
pub(crate) fn shell_read_execution_environment_is_safe(cwd: &PyPath, ctx: &Ctx) -> bool {
    if EXECUTION_ROUTING_ENVIRONMENT.iter().any(|key| {
        ctx.host
            .env(key)
            .is_some_and(|value| !crate::codex_output_py::py_strip(&value).is_empty())
    }) {
        return false;
    }
    for (key, value) in ctx.host.environment() {
        if value.is_empty()
            || !(key.starts_with("BASH_FUNC_")
                || key.starts_with("DYLD_")
                || key.starts_with("LD_"))
        {
            continue;
        }
        if !LOADER_PATH_ENVIRONMENT.contains(&key.as_str())
            || !trusted_loader_paths(&value, cwd, ctx)
        {
            return false;
        }
    }
    true
}

/// `_trusted_loader_paths`.
pub(crate) fn trusted_loader_paths(value: &str, cwd: &PyPath, ctx: &Ctx) -> bool {
    let paths: Vec<&str> = value.split(PATH_SEPARATOR).collect();
    if paths.iter().any(|item| item.is_empty()) {
        return false;
    }
    for item in paths {
        let mut candidate = PyPath::new(item);
        if !candidate.is_absolute() {
            candidate = cwd.join(item);
        }
        let Some(resolved) = resolve_existing(&candidate) else {
            return false;
        };
        let temp_root = gettempdir(ctx);
        let within = temp_root
            .as_ref()
            .is_some_and(|root| path_is_within(&resolved, root));
        if within
            || !ctx
                .host
                .git_binary_trusted(&resolved.to_string(), &cwd.to_string())
        {
            return false;
        }
    }
    true
}

/// `_path_is_within`: `root` must resolve (strict) and contain `path`.
pub(crate) fn path_is_within(path: &PyPath, root: &PyPath) -> bool {
    let Some(resolved_root) = resolve_existing(root) else {
        return false;
    };
    path.relative_to(&resolved_root).is_some()
}

/// `_trusted_pipeline_executables`.
pub(crate) fn trusted_pipeline_executables(names: &[&str], cwd: &PyPath, ctx: &Ctx) -> bool {
    for name in names {
        let Some(executable) = path_command_for_cwd(name, cwd, ctx) else {
            return false;
        };
        let Some(resolved) = resolve_existing(&PyPath::new(&executable)) else {
            return false;
        };
        if !ctx
            .host
            .git_binary_trusted(&resolved.to_string(), &cwd.to_string())
        {
            return false;
        }
    }
    true
}

/// `_path_command_for_cwd`.
pub(crate) fn path_command_for_cwd(name: &str, cwd: &PyPath, ctx: &Ctx) -> Option<String> {
    let search = ctx
        .host
        .env("PATH")
        .unwrap_or_else(|| DEFAULT_PATH.to_owned());
    for entry in search.split(PATH_SEPARATOR) {
        let mut directory = PyPath::new(if entry.is_empty() { "." } else { entry });
        if !directory.is_absolute() {
            directory = cwd.join(&directory.to_string());
        }
        let candidate = directory.join(name).to_string();
        if fs::metadata(&candidate).is_ok_and(|metadata| metadata.is_file())
            && is_executable(&candidate)
        {
            return Some(candidate);
        }
    }
    None
}
