//! macOS exposes the root temporary directory through the fixed system link
//! `/tmp -> /private/tmp`. A path spelled below `/tmp` names the same entry as
//! its `/private/tmp` spelling, so path proofs that refuse link components
//! map the alias first. Only that exact alias is mapped; every component
//! below it keeps its own link and location checks.

use std::path::{Path, PathBuf};

/// The `/private/tmp` spelling of a path spelled below macOS's `/tmp`
/// alias, when `/tmp` resolves to exactly `/private/tmp`. `None` for any
/// other spelling, and on every other platform.
pub(crate) fn private_tmp_spelling(supplied: &Path) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let alias = Path::new("/tmp");
        let relative = supplied.strip_prefix(alias).ok()?;
        let canonical = std::fs::canonicalize(alias).ok()?;
        (canonical == Path::new("/private/tmp")).then(|| canonical.join(relative))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = supplied;
        None
    }
}
