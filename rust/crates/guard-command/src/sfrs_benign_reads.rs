//! Explicitly benign request recognition
//! (`runtime/secret_file_request_services/benign_requests.py`).

// Items without a production caller yet are consumed by the later slices.
#![allow(dead_code)]

use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_fs as pyfs;
use crate::codex_output_py::{py_strip, PyPath};
use crate::codex_output_source_paths::{py_path, source_path_is_allowed_for_request};
use crate::hook_adapter_value::OValue;
use crate::sfrs_constants::{PATH_KEYS, PATH_LIST_KEYS};
use crate::sfrs_requests::normalize_tool_name;

const SHELL_META_MARKERS: &[&str] = &["$", "`", "<", ">", "|", ";", "&", "\u{0}"];

/// `is_explicitly_benign_native_file_read_request`: one existing,
/// non-sensitive native `Read` target.
pub(crate) fn is_explicitly_benign_native_file_read_request(
    tool_name: &OValue,
    arguments: &OValue,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    if normalize_tool_name(tool_name).as_deref() != Some("read") {
        return false;
    }
    let Some(arguments) = arguments.as_map() else {
        return false;
    };
    if PATH_LIST_KEYS.iter().any(|key| arguments.contains_key(key)) {
        return false;
    }
    let candidates: Vec<&str> = PATH_KEYS
        .iter()
        .filter_map(|key| arguments.get(key).and_then(OValue::non_blank_str))
        .map(py_strip)
        .collect();
    let [target] = candidates.as_slice() else {
        return false;
    };
    if SHELL_META_MARKERS
        .iter()
        .any(|marker| target.contains(marker))
    {
        return false;
    }
    let cwd = cwd.map(py_path);
    let home = home_dir.map(py_path);
    let decision =
        source_path_is_allowed_for_request(target, cwd.as_ref(), home.as_ref(), ctx, false);
    decision.allowed
        && decision
            .resolved_path
            .as_ref()
            .is_some_and(|resolved: &PyPath| pyfs::is_file(resolved) == Ok(true))
}
