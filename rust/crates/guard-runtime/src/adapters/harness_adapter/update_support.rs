//! What the `hol-guard update` repair ops share: the text a Python `OSError`
//! would print for a failed file operation.

use std::path::Path;

use super::{path_text, Ctx, Failure};

/// The `OSError` Python raised for `error` on `path`: `[Errno N] reason:
/// 'path'`, or `[WinError N] reason: 'path'` on Windows.
pub(super) fn os_failure(ctx: &Ctx, error: &std::io::Error, path: &Path) -> Failure {
    let text = error.to_string();
    let path = path_text(path);
    Failure::Os(match error.raw_os_error() {
        Some(code) => {
            let reason = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text);
            if ctx.windows {
                format!(
                    "[WinError {code}] {}: '{path}'",
                    reason.trim_end_matches('.')
                )
            } else {
                format!("[Errno {code}] {reason}: '{path}'")
            }
        }
        None => format!("{text}: '{path}'"),
    })
}
