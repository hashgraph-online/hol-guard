//! Environment-key and module-shadow probes the pytest safety checks use
//! (`interpreter_observers._shell_env_assignment_key`,
//! `_shell_segment_explicit_env_value`, `_python_module_may_be_shadowed` and
//! friends).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::env_wrapper::parse_env_wrapper;
use crate::sfrs_constants::SAFE_PYTHON_MODULE_SHADOW_PATHS;
use crate::sfrs_shell_tokens::{
    normalized_shell_command_name, shell_command_token_without_attached_redirection,
};

/// `_shell_env_assignment_key`.
pub(crate) fn shell_env_assignment_key(token: &str) -> Option<String> {
    let append_index = token.find("+=");
    let assignment_index = token.find('=');
    let key = match (append_index, assignment_index) {
        (Some(append), Some(assignment)) if append < assignment => {
            token.split_once("+=").map(|(key, _)| key)
        }
        (_, Some(_)) => token.split_once('=').map(|(key, _)| key),
        _ => None,
    }?;
    (!key.is_empty()).then(|| key.to_uppercase())
}

/// `_shell_segment_sets_env_key`.
pub(crate) fn shell_segment_sets_env_key(
    segment: &[String],
    command_index: usize,
    env_key: &str,
) -> bool {
    let (is_set, _value, complete) =
        shell_segment_explicit_env_value(segment, command_index, env_key);
    is_set || !complete
}

/// `_shell_segment_explicit_env_value`: `(is_set, value, complete)`.
pub(crate) fn shell_segment_explicit_env_value(
    segment: &[String],
    command_index: usize,
    env_key: &str,
) -> (bool, Option<String>, bool) {
    let normalized_key = env_key.to_uppercase();
    let mut is_set = false;
    let mut value: Option<String> = None;
    let mut index = 0;
    while index < command_index {
        let token = shell_command_token_without_attached_redirection(&segment[index]);
        if shell_env_assignment_key(&token).as_deref() == Some(normalized_key.as_str()) {
            is_set = true;
            value = Some(
                token
                    .split_once('=')
                    .map_or(String::new(), |(_, rest)| rest.to_owned()),
            );
            index += 1;
            continue;
        }
        if normalized_shell_command_name(&token) != "env" {
            index += 1;
            continue;
        }
        let parsed = parse_env_wrapper(&segment[index + 1..], None, None);
        if !parsed.complete {
            return (is_set, value, false);
        }
        if parsed.option_effects.ignore_environment
            || parsed
                .option_effects
                .unset_names
                .iter()
                .any(|name| name.to_uppercase() == normalized_key)
        {
            is_set = false;
            value = None;
        }
        for (name, assignment_value) in &parsed.environment_delta.assignments {
            if name.to_uppercase() == normalized_key {
                is_set = true;
                value = Some(assignment_value.clone());
            }
        }
        match parsed.command_index {
            Some(offset) if parsed.split_expansions.is_empty() => index += offset + 1,
            _ => break,
        }
    }
    (is_set, value, true)
}

/// `_pytest_local_entry_point_metadata_exists`; an unreadable directory is
/// treated as holding one.
fn pytest_local_entry_point_metadata_exists(cwd: &PyPath) -> bool {
    let Ok(entries) = std::fs::read_dir(cwd.to_string()) else {
        return true;
    };
    for entry in entries {
        let Ok(entry) = entry else { return true };
        let child = cwd.join(&entry.file_name().to_string_lossy());
        match pyfs::is_dir(&child) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(()) => return true,
        }
        let name = child.name();
        if !(name.ends_with(".dist-info") || name.ends_with(".egg-info")) {
            continue;
        }
        match pyfs::exists(&child.join("entry_points.txt")) {
            Ok(true) => return true,
            Ok(false) => {}
            Err(()) => return true,
        }
    }
    false
}

/// `_python_module_may_be_shadowed`.
pub(crate) fn python_module_may_be_shadowed(module_root: &str, cwd: Option<&PyPath>) -> bool {
    let roots: Vec<PyPath> = cwd.cloned().into_iter().collect();
    python_module_may_be_shadowed_in_search_roots(module_root, &roots)
}

/// `_python_module_may_be_shadowed_in_search_roots`.
pub(crate) fn python_module_may_be_shadowed_in_search_roots(
    module_root: &str,
    search_roots: &[PyPath],
) -> bool {
    if search_roots.is_empty() {
        return true;
    }
    let Some((_, shadow_paths)) = SAFE_PYTHON_MODULE_SHADOW_PATHS
        .iter()
        .find(|(name, _)| *name == module_root)
    else {
        return true;
    };
    for search_root in search_roots {
        if module_root == "pytest" && pytest_local_entry_point_metadata_exists(search_root) {
            return true;
        }
        for shadow_path in *shadow_paths {
            match pyfs::exists(&search_root.join(shadow_path)) {
                Ok(false) => {}
                Ok(true) | Err(()) => return true,
            }
        }
    }
    false
}
