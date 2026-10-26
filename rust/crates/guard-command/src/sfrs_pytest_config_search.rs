//! Pytest config selection by command arguments
//! (`secret_file_request_services/pytest_config_safety.py`): explicit
//! `-c`/`--config-file` paths, the `rootdir`-style search directories and the
//! positional arguments.

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_constants::{
    PYTEST_OPTION_CONFIG_PATHS, PYTEST_SAFE_FLAGS, PYTEST_SAFE_FLAGS_WITH_VALUES,
};
use crate::sfrs_pytest_config::{
    assess_pytest_configs, assess_selected_pytest_config, PytestConfigAssessment,
};
use crate::sfrs_pytest_config_safety::{char_len, INVALID_SEARCH};

/// `_pytest_config_assessment`.
pub(crate) fn pytest_config_assessment(
    cwd: &Path,
    module_args: &[String],
) -> PytestConfigAssessment {
    let invalid = || assess_pytest_configs(cwd, &[INVALID_SEARCH.to_owned()], false);
    let Some(explicit) = pytest_explicit_config_paths(module_args, cwd) else {
        return invalid();
    };
    if !explicit.is_empty() {
        return assess_pytest_configs(cwd, &explicit, true);
    }
    let Some(config_dirs) = pytest_config_search_dirs(module_args, cwd) else {
        return invalid();
    };
    let candidates: Vec<String> = config_dirs
        .iter()
        .flat_map(|config_dir| {
            PYTEST_OPTION_CONFIG_PATHS
                .iter()
                .map(move |config_path| PyPath::new(config_dir).join(config_path).to_string())
        })
        .collect();
    assess_selected_pytest_config(cwd, &candidates)
}

/// `_pytest_explicit_config_paths`; `None` is an unusable option.
pub(crate) fn pytest_explicit_config_paths(
    module_args: &[String],
    cwd: &Path,
) -> Option<Vec<String>> {
    let mut paths: Vec<String> = Vec::new();
    let mut index = 0;
    while index < module_args.len() {
        let token = module_args[index].as_str();
        let path_text: &str;
        if token == "-c" || token == "--config-file" {
            path_text = module_args.get(index + 1)?;
            index += 2;
        } else if let Some(rest) = token.strip_prefix("--config-file=") {
            path_text = rest;
            index += 1;
        } else if let Some(rest) = token.strip_prefix("-c=") {
            path_text = rest;
            index += 1;
        } else if token.starts_with("-c") && char_len(token) > 2 {
            path_text = &token[2..];
            index += 1;
        } else {
            index += 1;
            continue;
        }
        let selected = pytest_selected_relative_path(path_text, cwd)?;
        if selected.is_empty() {
            return None;
        }
        paths.push(selected);
    }
    Some(paths.pop().into_iter().collect())
}

/// `_pytest_config_search_dirs`.
pub(crate) fn pytest_config_search_dirs(module_args: &[String], cwd: &Path) -> Option<Vec<String>> {
    let positional = pytest_positional_args(module_args);
    if positional.is_empty() {
        return Some(vec![String::new()]);
    }
    let base = PyPath::new(&cwd.to_string_lossy());
    let mut selected_paths: Vec<String> = Vec::new();
    for module_arg in &positional {
        let selected = pytest_selected_relative_path(module_arg, cwd)?;
        if selected.is_empty() {
            continue;
        }
        let mut config_root = PyPath::new(&selected);
        match pyfs::is_dir(&base.join(&config_root.to_string())) {
            Ok(true) => {}
            Ok(false) => config_root = config_root.parent(),
            Err(()) => return None,
        }
        let text = config_root.to_string();
        selected_paths.push(if text == "." { String::new() } else { text });
    }
    if selected_paths.is_empty() {
        return Some(vec![String::new()]);
    }
    Some(pytest_config_ancestor_dirs(&PyPath::new(
        &relative_commonpath(&selected_paths),
    )))
}

/// `os.path.commonpath` over relative POSIX paths.
fn relative_commonpath(paths: &[String]) -> String {
    let split: Vec<Vec<&str>> = paths
        .iter()
        .map(|path| {
            path.split('/')
                .filter(|part| !part.is_empty() && *part != ".")
                .collect()
        })
        .collect();
    let smallest = split.iter().min().expect("paths");
    let largest = split.iter().max().expect("paths");
    let mut common = smallest.as_slice();
    for (position, component) in smallest.iter().enumerate() {
        if largest.get(position) != Some(component) {
            common = &smallest[..position];
            break;
        }
    }
    common.join("/")
}

/// `_pytest_selected_relative_path`; `None` leaves the workspace.
pub(crate) fn pytest_selected_relative_path(module_arg: &str, cwd: &Path) -> Option<String> {
    let path_text = module_arg.split("::").next().unwrap_or("");
    if path_text.is_empty() {
        return Some(String::new());
    }
    let path = PyPath::new(path_text);
    if path.components().iter().any(|part| part == "..") {
        return None;
    }
    if !path.is_absolute() {
        return Some(path.to_string());
    }
    let cwd_text = PyPath::new(&cwd.to_string_lossy()).to_string();
    let path_text = path.to_string();
    if path_text == cwd_text {
        return Some(String::new());
    }
    let prefix = format!("{cwd_text}/");
    let relative_text = path_text.strip_prefix(prefix.as_str())?;
    let relative = PyPath::new(relative_text);
    if relative.is_absolute() || relative.components().iter().any(|part| part == "..") {
        return None;
    }
    Some(relative.to_string())
}

/// `_pytest_config_ancestor_dirs`.
pub(crate) fn pytest_config_ancestor_dirs(root: &PyPath) -> Vec<String> {
    let text = root.to_string();
    if text.is_empty() || text == "." {
        return vec![String::new()];
    }
    let mut dirs = Vec::new();
    let mut current = root.clone();
    loop {
        let text = current.to_string();
        if text.is_empty() || text == "." {
            break;
        }
        dirs.push(text);
        let parent = current.parent();
        // Python never terminates on an absolute root; stop instead.
        if parent.to_string() == dirs[dirs.len() - 1] {
            break;
        }
        current = parent;
    }
    dirs.push(String::new());
    dirs
}

/// `_pytest_positional_args`.
pub(crate) fn pytest_positional_args(module_args: &[String]) -> Vec<String> {
    let mut positional = Vec::new();
    let mut index = 0;
    while index < module_args.len() {
        let arg = module_args[index].as_str();
        if arg == "--" {
            return positional;
        }
        if PYTEST_SAFE_FLAGS.contains(&arg) {
            index += 1;
            continue;
        }
        if PYTEST_SAFE_FLAGS_WITH_VALUES.contains(&arg) || arg == "-c" || arg == "--config-file" {
            index += 2;
            continue;
        }
        if has_safe_value_flag_prefix(arg) {
            index += 1;
            continue;
        }
        if !arg.starts_with('-') {
            positional.push(arg.to_owned());
        }
        index += 1;
    }
    positional
}

pub(crate) fn has_safe_value_flag_prefix(arg: &str) -> bool {
    PYTEST_SAFE_FLAGS_WITH_VALUES.iter().any(|flag| {
        arg.strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('='))
    })
}
