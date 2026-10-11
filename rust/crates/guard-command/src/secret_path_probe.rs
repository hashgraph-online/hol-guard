//! Public probe over the secret path classifier for callers outside this crate.

use std::path::Path;

use crate::shell_secret_read_support::classify_secret_path;

/// Whether `path` names a sensitive secret location (`classify_secret_path`
/// returns a match). `cwd` anchors relative paths and `home_dir` expands `~`.
#[must_use]
pub fn is_secret_path(path: &str, cwd: Option<&Path>, home_dir: Option<&Path>) -> bool {
    classify_secret_path(path, cwd, home_dir).is_some()
}
