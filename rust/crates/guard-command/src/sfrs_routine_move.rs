//! Conservative classification of routine local filesystem moves
//! (`secret_file_request_services/routine_move.py`).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::PyPath;
use crate::sfrs_requests::classify_sensitive_path;
use crate::sfrs_shell_tokens::{iter_shell_command_segments, shell_segment_primary_command};

const UNSAFE_PATH_CHARACTERS: [char; 10] = ['*', '?', '[', ']', '{', '}', '$', '`', '\n', '\r'];
const SENSITIVE_DIRECTORY_NAMES: [&str; 6] =
    [".aws", ".codex", ".docker", ".hol-guard", ".kube", ".ssh"];
const GENERATED_DIRECTORY_NAMES: [&str; 5] = [".cache", ".next", "build", "coverage", "dist"];

/// `_looks_like_safe_routine_move`: one bounded, non-overwriting `mv` rename.
pub(crate) fn looks_like_safe_routine_move(
    parts: &[String],
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let Some(cwd) = cwd else {
        return false;
    };
    let segments = iter_shell_command_segments(parts);
    if segments.len() != 1 {
        return false;
    }
    let segment = &segments[0];
    let (command_name, command_index) = shell_segment_primary_command(segment);
    if command_name.as_deref() != Some("mv") || command_index != Some(0) {
        return false;
    }
    let mut operands = &segment[1..];
    if operands.first().is_some_and(|first| first == "--") {
        operands = &operands[1..];
    }
    if operands.len() != 2 || operands.iter().any(|operand| operand.starts_with('-')) {
        return false;
    }
    let (source_text, destination_text) = (&operands[0], &operands[1]);
    if !move_operand_is_static(source_text) || !move_operand_is_static(destination_text) {
        return false;
    }
    if classify_sensitive_path(source_text, Some(cwd), home_dir).is_some()
        || classify_sensitive_path(destination_text, Some(cwd), home_dir).is_some()
    {
        return false;
    }
    let cwd_path = absolute(&PyPath::new(&cwd.to_string_lossy()), ctx);
    let (Some(source_candidate), Some(destination_candidate)) = (
        move_operand_candidate(source_text, &cwd_path, home_dir),
        move_operand_candidate(destination_text, &cwd_path, home_dir),
    ) else {
        return false;
    };
    let source_candidate = absolute(&source_candidate, ctx);
    let destination_candidate = absolute(&destination_candidate, ctx);
    if fs::symlink_metadata(destination_candidate.to_string()).is_ok() {
        return false;
    }
    let (Some(source), Some(destination)) = (
        resolve_move_candidate(&source_candidate, true),
        resolve_move_candidate(&destination_candidate, false),
    ) else {
        return false;
    };
    if pyfs::exists(&destination) != Ok(false) {
        return false;
    }
    if path_contains_sensitive_directory(&source) || path_contains_sensitive_directory(&destination)
    {
        return false;
    }
    if resolve_move_candidate(&destination_candidate.parent(), true).is_none() {
        return false;
    }
    let Some(workspace) = pyfs::resolve(&cwd_path) else {
        return false;
    };
    if source == workspace || destination == workspace {
        return false;
    }
    if path_is_within(&source, &workspace) && path_is_within(&destination, &workspace) {
        return true;
    }
    let Some(temporary_root) = temporary_root(ctx) else {
        return false;
    };
    GENERATED_DIRECTORY_NAMES.contains(&source.name())
        && path_is_within(&source, &workspace)
        && path_is_within(&destination, &temporary_root)
}

/// `_move_operand_is_static`.
pub(crate) fn move_operand_is_static(operand: &str) -> bool {
    !operand.is_empty()
        && !operand.contains("...")
        && !operand.chars().any(|c| UNSAFE_PATH_CHARACTERS.contains(&c))
}

/// `_path_contains_sensitive_directory`.
pub(crate) fn path_contains_sensitive_directory(path: &PyPath) -> bool {
    path.parts()
        .iter()
        .any(|part| SENSITIVE_DIRECTORY_NAMES.contains(&part.to_lowercase().as_str()))
}

/// `_move_operand_candidate`: `~` and `~/` use the supplied home directory.
pub(crate) fn move_operand_candidate(
    operand: &str,
    cwd: &PyPath,
    home_dir: Option<&Path>,
) -> Option<PyPath> {
    if operand == "~" || operand.starts_with("~/") {
        let home = PyPath::new(&home_dir?.to_string_lossy());
        return Some(match operand.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => home,
        });
    }
    let candidate = PyPath::new(operand);
    Some(if candidate.is_absolute() {
        candidate
    } else {
        cwd.join(operand)
    })
}

/// `_resolve_move_candidate`; `None` is `OSError` or `RuntimeError`.
pub(crate) fn resolve_move_candidate(candidate: &PyPath, strict: bool) -> Option<PyPath> {
    if strict {
        let resolved = fs::canonicalize(candidate.to_string()).ok()?;
        return Some(PyPath::new(&resolved.to_string_lossy()));
    }
    pyfs::resolve(candidate)
}

/// `_path_is_within`: `Path.relative_to` succeeds.
pub(crate) fn path_is_within(path: &PyPath, boundary: &PyPath) -> bool {
    path.relative_to(boundary).is_some()
}

fn absolute(path: &PyPath, ctx: &Ctx) -> PyPath {
    if path.is_absolute() {
        path.clone()
    } else {
        ctx.process_cwd.join(&path.to_string())
    }
}

/// `Path(tempfile.gettempdir()).resolve()`: the first usable candidate.
fn temporary_root(ctx: &Ctx) -> Option<PyPath> {
    let mut candidates: Vec<String> = ["TMPDIR", "TEMP", "TMP"]
        .iter()
        .filter_map(|name| ctx.host.env(name))
        .filter(|value| !value.is_empty())
        .collect();
    candidates.extend(["/tmp", "/var/tmp", "/usr/tmp"].map(str::to_owned));
    candidates.push(ctx.process_cwd.to_string());
    for candidate in candidates {
        let path = absolute(&PyPath::new(&candidate), ctx);
        let Some(resolved) = pyfs::resolve(&path) else {
            continue;
        };
        if directory_is_writable(&resolved) {
            return Some(resolved);
        }
    }
    None
}

fn directory_is_writable(path: &PyPath) -> bool {
    let name = PathBuf::from(path.to_string()).join(format!(".sfrs-probe-{}", std::process::id()));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&name)
    {
        Ok(_) => {
            let _ = fs::remove_file(&name);
            true
        }
        Err(_) => false,
    }
}
