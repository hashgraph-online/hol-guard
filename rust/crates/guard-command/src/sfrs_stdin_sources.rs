//! Shell stdin and stdout payload tracing (`shell_stdin_sources.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::runtime_read_paths::{read_small_runtime_text_file, resolved_runtime_path};
use crate::sfrs_credential_exfil::{effective_read_roots, py_parent};
use crate::sfrs_network_upload::{
    looks_like_local_stdin_source, stdin_redirect_uses_local_file, StdinPayload,
};
use crate::sfrs_shell_tokens::{shell_segment_primary_command, stdin_redirect_target_from_token};
use crate::sfrs_upload_arguments::strip_cli_value;

/// `_shell_pipeline_stdin_uses_local_file`.
pub(crate) fn shell_pipeline_stdin_uses_local_file(
    pipeline: &[Vec<String>],
    index: usize,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    let mut stdin_uses_local_file = false;
    for upstream in &pipeline[..index] {
        stdin_uses_local_file =
            shell_segment_stdout_uses_local_file(upstream, stdin_uses_local_file, cwd, home_dir);
    }
    stdin_uses_local_file || shell_stdin_redirect_uses_local_file(&pipeline[index], cwd, home_dir)
}

/// `_shell_pipeline_stdin_payloads`.
pub(crate) fn shell_pipeline_stdin_payloads(
    pipeline: &[Vec<String>],
    index: usize,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> Vec<StdinPayload> {
    let mut payloads: Vec<StdinPayload> = Vec::new();
    for upstream in &pipeline[..index] {
        payloads = shell_segment_stdout_payloads(upstream, payloads, cwd, home_dir, allowed_roots);
    }
    let redirected = shell_stdin_redirect_payloads(&pipeline[index], cwd, home_dir, allowed_roots);
    if redirected.is_empty() {
        payloads
    } else {
        redirected
    }
}

/// `_shell_segment_stdout_payloads`.
pub(crate) fn shell_segment_stdout_payloads(
    segment: &[String],
    stdin_payloads: Vec<StdinPayload>,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> Vec<StdinPayload> {
    let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment) else {
        return stdin_payloads;
    };
    let segment_args = &segment[command_index + 1..];
    let redirected = shell_stdin_redirect_payloads(segment, cwd, home_dir, allowed_roots);
    let effective = if redirected.is_empty() {
        stdin_payloads
    } else {
        redirected
    };
    let owned_cwd = cwd.map(Path::to_path_buf);
    match command_name.as_str() {
        "printf" => printf_stdout_payloads(segment_args)
            .into_iter()
            .map(|payload| (payload, owned_cwd.clone()))
            .collect(),
        "echo" => match echo_stdout_payload(segment_args) {
            Some(payload) if !payload.is_empty() => vec![(payload, owned_cwd)],
            _ => Vec::new(),
        },
        "cat" => {
            let from_files = cat_stdout_payloads(segment_args, cwd, home_dir, allowed_roots);
            if from_files.is_empty() {
                effective
            } else {
                from_files
            }
        }
        "sed" | "tr" => effective,
        _ => Vec::new(),
    }
}

/// `_shell_segment_stdout_uses_local_file`.
pub(crate) fn shell_segment_stdout_uses_local_file(
    segment: &[String],
    stdin_uses_local_file: bool,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
) -> bool {
    let (Some(command_name), Some(command_index)) = shell_segment_primary_command(segment) else {
        return stdin_uses_local_file;
    };
    if shell_stdin_redirect_uses_local_file(segment, cwd, home_dir) {
        return true;
    }
    let segment_args = &segment[command_index + 1..];
    match command_name.as_str() {
        "cat" => cat_reads_local_file(segment_args) || stdin_uses_local_file,
        "echo" | "printf" => false,
        _ => stdin_uses_local_file,
    }
}

/// `_printf_stdout_payloads`.
pub(crate) fn printf_stdout_payloads(segment_args: &[String]) -> Vec<String> {
    let args: &[String] = if segment_args.first().is_some_and(|arg| arg == "--") {
        &segment_args[1..]
    } else {
        segment_args
    };
    let decoded: Vec<String> = args
        .iter()
        .filter_map(|arg| decode_shell_text_literal(arg))
        .filter(|text| !text.is_empty())
        .collect();
    if decoded.len() <= 1 {
        return decoded;
    }
    let joined = decoded.join("\n");
    let mut payloads = decoded;
    payloads.push(joined);
    payloads
}

/// `_echo_stdout_payload`.
pub(crate) fn echo_stdout_payload(segment_args: &[String]) -> Option<String> {
    let mut args = segment_args;
    while args
        .first()
        .is_some_and(|arg| matches!(arg.as_str(), "-n" | "-e" | "-E"))
    {
        args = &args[1..];
    }
    if args.is_empty() {
        return None;
    }
    let decoded: Vec<String> = args
        .iter()
        .filter_map(|arg| decode_shell_text_literal(arg))
        .filter(|text| !text.is_empty())
        .collect();
    if decoded.is_empty() {
        None
    } else {
        Some(decoded.join(" "))
    }
}

/// `_cat_stdout_payloads`.
pub(crate) fn cat_stdout_payloads(
    segment_args: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> Vec<StdinPayload> {
    let mut payloads: Vec<StdinPayload> = Vec::new();
    let mut consume_all = false;
    let read_roots = effective_read_roots(allowed_roots, cwd, home_dir);
    for token in segment_args {
        if token == "--" {
            consume_all = true;
            continue;
        }
        if (!consume_all && token.starts_with('-')) || token == "-" {
            continue;
        }
        let Some(config_path) = resolved_runtime_path(token, cwd, home_dir, Some(&read_roots))
        else {
            continue;
        };
        let Some(text) = read_small_runtime_text_file(&config_path, &read_roots) else {
            continue;
        };
        payloads.push((text, Some(py_parent(&config_path))));
    }
    payloads
}

/// `_cat_reads_local_file`.
pub(crate) fn cat_reads_local_file(segment_args: &[String]) -> bool {
    let mut consume_all = false;
    for token in segment_args {
        if token == "--" {
            consume_all = true;
            continue;
        }
        if (!consume_all && token.starts_with('-')) || token == "-" {
            continue;
        }
        if looks_like_local_stdin_source(token) {
            return true;
        }
    }
    false
}

/// `_shell_stdin_redirect_payloads`.
pub(crate) fn shell_stdin_redirect_payloads(
    segment: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> Vec<StdinPayload> {
    let mut payloads: Vec<StdinPayload> = Vec::new();
    let owned_cwd = cwd.map(Path::to_path_buf);
    let mut index = 0;
    while index < segment.len() {
        let token = segment[index].as_str();
        if token == "<<<" && index + 1 < segment.len() {
            if let Some(text) = decode_shell_text_literal(&segment[index + 1]) {
                if !text.is_empty() {
                    payloads.push((text, owned_cwd.clone()));
                }
            }
            index += 2;
            continue;
        }
        if let Some(literal) = token.strip_prefix("<<<") {
            if let Some(text) = decode_shell_text_literal(literal) {
                if !text.is_empty() {
                    payloads.push((text, owned_cwd.clone()));
                }
            }
            index += 1;
            continue;
        }
        let next_token = segment.get(index + 1).map(String::as_str);
        let (target, consumed) = stdin_redirect_target_from_token(token, next_token);
        if let Some(target) = target {
            if let Some(payload) = stdin_redirect_payload(&target, cwd, home_dir, allowed_roots) {
                payloads.push(payload);
            }
            index += consumed;
            continue;
        }
        index += 1;
    }
    payloads
}

/// `_shell_stdin_redirect_uses_local_file`.
pub(crate) fn shell_stdin_redirect_uses_local_file(
    segment: &[String],
    _cwd: Option<&Path>,
    _home_dir: Option<&Path>,
) -> bool {
    let mut index = 0;
    while index < segment.len() {
        let token = segment[index].as_str();
        if token == "<" && index + 1 < segment.len() {
            if stdin_redirect_uses_local_file(&segment[index + 1]) {
                return true;
            }
            index += 2;
            continue;
        }
        let next_token = segment.get(index + 1).map(String::as_str);
        let (target, consumed) = stdin_redirect_target_from_token(token, next_token);
        if let Some(target) = target {
            if stdin_redirect_uses_local_file(&target) {
                return true;
            }
            index += consumed;
        } else {
            index += 1;
        }
    }
    false
}

/// `_stdin_redirect_payload`.
pub(crate) fn stdin_redirect_payload(
    target: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> Option<StdinPayload> {
    let read_roots = effective_read_roots(allowed_roots, cwd, home_dir);
    let config_path = resolved_runtime_path(target, cwd, home_dir, Some(&read_roots))?;
    let text = read_small_runtime_text_file(&config_path, &read_roots)?;
    Some((text, Some(py_parent(&config_path))))
}

/// `_decode_shell_text_literal`: `bytes(value, "utf-8").decode("unicode_escape")`,
/// falling back to the stripped value on a decode error.
pub(crate) fn decode_shell_text_literal(value: &str) -> Option<String> {
    let stripped = strip_cli_value(value);
    if stripped.is_empty() {
        return None;
    }
    Some(unicode_escape_decode(&stripped).unwrap_or(stripped))
}

fn hex_value(bytes: &[u8], start: usize, width: usize) -> Option<u32> {
    let digits = bytes.get(start..start + width)?;
    let mut value: u32 = 0;
    for digit in digits {
        value = value
            .checked_mul(16)?
            .checked_add(char::from(*digit).to_digit(16)?)?;
    }
    Some(value)
}

/// CPython's `unicode_escape` decoder over the UTF-8 bytes of `text` (each
/// byte is a Latin-1 character). `None` is a `UnicodeDecodeError`. `\N{..}`
/// needs the Unicode name table and is reported as an error; lone surrogate
/// escapes become U+FFFD.
pub(crate) fn unicode_escape_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if byte != b'\\' {
            out.push(char::from(byte));
            continue;
        }
        let escape = *bytes.get(index)?;
        index += 1;
        match escape {
            b'\n' => {}
            b'\\' | b'\'' | b'"' => out.push(char::from(escape)),
            b'a' => out.push('\u{07}'),
            b'b' => out.push('\u{08}'),
            b'f' => out.push('\u{0c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'v' => out.push('\u{0b}'),
            b'0'..=b'7' => {
                let mut value = u32::from(escape - b'0');
                for _ in 0..2 {
                    match bytes.get(index) {
                        Some(digit @ b'0'..=b'7') => {
                            value = value * 8 + u32::from(digit - b'0');
                            index += 1;
                        }
                        _ => break,
                    }
                }
                out.push(char::from_u32(value)?);
            }
            b'x' | b'u' | b'U' => {
                let width = match escape {
                    b'x' => 2,
                    b'u' => 4,
                    _ => 8,
                };
                let value = hex_value(bytes, index, width)?;
                index += width;
                if value > 0x10_ffff {
                    return None;
                }
                out.push(char::from_u32(value).unwrap_or('\u{fffd}'));
            }
            b'N' => return None,
            other => {
                out.push('\\');
                out.push(char::from(other));
            }
        }
    }
    Some(out)
}
