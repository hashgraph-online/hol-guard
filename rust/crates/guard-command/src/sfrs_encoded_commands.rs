//! Encoded or encrypted shell command detection (`upload_arguments.py`:
//! `_contains_encoded_or_encrypted_shell_command` and its payload check).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::codex_output_py::py_strip;
use crate::sfrs_credential_exfil::local_shell_script_payloads;
use crate::sfrs_encoded_payloads::{
    contains_command_substitution_decode_exec, decoded_shell_payloads, pattern_found,
    shell_text_without_quoted_literals, DestructiveCheck,
};
use crate::sfrs_request_data::{ENCODED_EXECUTION_PATTERNS, SENSITIVE_DECODED_PAYLOAD_TOKENS};
use crate::sfrs_shell_tokens::split_shell_parts;
use crate::sfrs_substitution::{env_split_string_payloads, shell_command_scripts};

/// The keyword arguments `_contains_encoded_or_encrypted_shell_command`
/// threads through its recursion, plus the destructive-command check.
#[derive(Clone, Copy)]
pub(crate) struct EncodedScan<'a> {
    pub(crate) cwd: Option<&'a Path>,
    pub(crate) home_dir: Option<&'a Path>,
    pub(crate) allowed_roots: Option<&'a [PathBuf]>,
    pub(crate) visited_script_paths: &'a [String],
    pub(crate) destructive: DestructiveCheck<'a>,
}

/// `_contains_encoded_or_encrypted_shell_command`.
pub(crate) fn contains_encoded_or_encrypted_shell_command(
    command_text: &str,
    scan: &EncodedScan<'_>,
    depth: usize,
) -> bool {
    if depth > 4 {
        return false;
    }
    let normalized = py_strip(command_text);
    if normalized.is_empty() {
        return false;
    }
    let executable_surface = shell_text_without_quoted_literals(normalized);
    if ENCODED_EXECUTION_PATTERNS
        .iter()
        .any(|pattern| pattern_found(pattern, &executable_surface))
    {
        return true;
    }
    if contains_command_substitution_decode_exec(normalized) {
        return true;
    }
    let parts = split_shell_parts(normalized);
    if parts.is_empty() {
        return false;
    }
    for payload in decoded_shell_payloads(&executable_surface) {
        if decoded_payload_looks_sensitive(&payload, scan, depth + 1) {
            return true;
        }
    }
    for text in env_split_string_payloads(&parts)
        .into_iter()
        .chain(shell_command_scripts(&parts))
    {
        if contains_encoded_or_encrypted_shell_command(&text, scan, depth + 1) {
            return true;
        }
    }
    for (script_text, script_cwd, script_path) in local_shell_script_payloads(
        &parts,
        scan.cwd,
        scan.home_dir,
        scan.allowed_roots,
        scan.visited_script_paths,
    ) {
        let mut visited = scan.visited_script_paths.to_vec();
        visited.push(script_path);
        let nested = EncodedScan {
            cwd: script_cwd.as_deref(),
            visited_script_paths: &visited,
            ..*scan
        };
        if contains_encoded_or_encrypted_shell_command(&script_text, &nested, depth + 1) {
            return true;
        }
    }
    false
}

/// `_decoded_payload_looks_sensitive`. The nested encoded check does not
/// forward `allowed_roots`, as in the original.
pub(crate) fn decoded_payload_looks_sensitive(
    payload: &str,
    scan: &EncodedScan<'_>,
    depth: usize,
) -> bool {
    let lowered = payload.to_lowercase();
    if (scan.destructive)(payload, scan.cwd, scan.home_dir) {
        return true;
    }
    if SENSITIVE_DECODED_PAYLOAD_TOKENS
        .iter()
        .any(|token| lowered.contains(token))
    {
        return true;
    }
    let nested = EncodedScan {
        allowed_roots: None,
        ..*scan
    };
    contains_encoded_or_encrypted_shell_command(payload, &nested, depth)
}
