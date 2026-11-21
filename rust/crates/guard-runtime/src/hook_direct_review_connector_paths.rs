//! The path and label spellings the connector-setup lookup must reproduce
//! byte for byte from the daemon (`native_review_connector.py`). Part of the
//! resident's connector-setup review (`hook_direct_review_connector.rs`).

use serde_json::{Map, Value};

use super::HookDirectDefer;
use crate::guard_store_connector_context::{scrub_context_text, MAX_LABEL_CHARS};

/// `scrub_connector_context_text(value, limit=MAX_LABEL_CHARS)`, the scrub
/// the daemon applies before it sends a label. Only printable ASCII is
/// scrubbed here, where Python's and the resident's character classes agree;
/// any other label defers.
pub(super) fn label(text: &str) -> Result<Option<String>, HookDirectDefer> {
    if !text.chars().all(|item| (' '..='~').contains(&item)) {
        return Err(HookDirectDefer::ReviewQueue);
    }
    Ok(scrub_context_text(text, MAX_LABEL_CHARS))
}

/// Whether `str(Path(path)) == path`: an absolute path with no empty or `.`
/// component and no trailing separator.
#[cfg(not(windows))]
pub(super) fn pathlib_normal(path: &str) -> bool {
    path == "/"
        || path
            .strip_prefix('/')
            .is_some_and(|rest| rest.split('/').all(|part| !part.is_empty() && part != "."))
}

/// Whether `str(Path(path)) == path` for a drive-letter path: `X:\` and
/// components with no empty or `.` one. A UNC, verbatim or `/` spelling is
/// not reproduced.
#[cfg(windows)]
pub(super) fn pathlib_normal(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
        || path.contains('/')
    {
        return false;
    }
    let rest = &path[3..];
    rest.is_empty() || rest.split('\\').all(|part| !part.is_empty() && part != ".")
}

/// `Path(path).name` for a path [`pathlib_normal`] accepts.
pub(super) fn pathlib_name(path: &str) -> &str {
    let separator = if cfg!(windows) { '\\' } else { '/' };
    path.rsplit(separator).next().unwrap_or_default()
}

/// `launch_path`: the `PATH` the hook stamped from the agent's environment.
pub(super) fn launch_path(payload: &Map<String, Value>) -> Option<&str> {
    payload
        .get(crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD)?
        .get("path")?
        .as_str()
        .filter(|path| !path.is_empty() && !path.contains('\0'))
}
