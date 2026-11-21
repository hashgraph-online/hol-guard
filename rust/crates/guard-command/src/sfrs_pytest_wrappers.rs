//! Directory-setup and cwd-changing wrapper checks of the pytest binary safety
//! (`secret_file_request_services/pytest_binary_safety.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use crate::env_wrapper::parse_env_wrapper;
use crate::sfrs_pytest_config_safety::shell_args_without_trailing_redirections;
use crate::sfrs_shell_tokens::{
    normalized_shell_command_name, shell_command_token_without_attached_redirection,
    wrapper_option_tokens_consumed,
};
use crate::sfrs_static_safety::shell_token_has_command_substitution;

/// `_shell_directory_setup_segment_is_safe`.
pub(crate) fn shell_directory_setup_segment_is_safe(
    command_name: &str,
    segment_args: &[String],
) -> bool {
    if command_name == "popd" {
        let path_args = shell_args_without_trailing_redirections(segment_args);
        return path_args
            .iter()
            .all(|token| !shell_token_has_command_substitution(token));
    }
    if command_name != "cd" && command_name != "pushd" {
        return false;
    }
    let path_args = shell_args_without_trailing_redirections(segment_args);
    if path_args.is_empty() {
        return false;
    }
    for token in &path_args {
        if token == "-" || token == "--" {
            continue;
        }
        if token.starts_with('-') || shell_token_has_command_substitution(token) {
            return false;
        }
    }
    true
}

fn wrapper_name(token: &str) -> String {
    normalized_shell_command_name(&shell_command_token_without_attached_redirection(token))
}

/// `_shell_segment_uses_env_split_string_wrapper`.
pub(crate) fn shell_segment_uses_env_split_string_wrapper(
    segment: &[String],
    command_index: usize,
) -> bool {
    let mut index = 0;
    while index < command_index {
        if wrapper_name(&segment[index]) != "env" {
            index += 1;
            continue;
        }
        let parsed = parse_env_wrapper(&segment[index + 1..], None, None);
        if !parsed.split_expansions.is_empty() {
            return true;
        }
        match parsed.command_index {
            Some(offset) if parsed.complete => index += offset + 1,
            _ => break,
        }
    }
    false
}

/// `_shell_segment_uses_env_chdir`.
pub(crate) fn shell_segment_uses_env_chdir(segment: &[String], command_index: usize) -> bool {
    let mut index = 0;
    while index < command_index {
        if wrapper_name(&segment[index]) != "env" {
            index += 1;
            continue;
        }
        let parsed = parse_env_wrapper(&segment[index + 1..], None, None);
        if parsed.option_effects.chdir.is_some() {
            return true;
        }
        match parsed.command_index {
            Some(offset) if parsed.complete && parsed.split_expansions.is_empty() => {
                index += offset + 1;
            }
            _ => break,
        }
    }
    false
}

/// `_shell_segment_uses_sudo_chdir`.
pub(crate) fn shell_segment_uses_sudo_chdir(segment: &[String], command_index: usize) -> bool {
    let mut index = 0;
    while index < command_index {
        if wrapper_name(&segment[index]) != "sudo" {
            index += 1;
            continue;
        }
        index += 1;
        while index < command_index {
            let token = segment[index].as_str();
            if token == "-D"
                || token == "--chdir"
                || token.starts_with("-D")
                || token.starts_with("--chdir=")
            {
                return true;
            }
            if !token.starts_with('-') {
                break;
            }
            index += wrapper_option_tokens_consumed("sudo", token).max(1);
        }
    }
    false
}

/// `_shell_segment_uses_cwd_changing_wrapper`.
pub(crate) fn shell_segment_uses_cwd_changing_wrapper(
    segment: &[String],
    command_index: usize,
) -> bool {
    shell_segment_uses_env_chdir(segment, command_index)
        || shell_segment_uses_sudo_chdir(segment, command_index)
}
