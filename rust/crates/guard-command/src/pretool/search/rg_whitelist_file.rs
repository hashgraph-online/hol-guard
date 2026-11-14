//! A hidden file an ignore rule re-includes, held to the screen `rg` gives
//! the same file named as an operand.
//!
//! A repository that commits a hidden fixture often has to re-include it by
//! path (`!tests/fixtures/kit/.mcp.json`). `rg PATTERN tests/fixtures/kit/.mcp.json`
//! already passes the operand screen, so the walk of `rg PATTERN tests` that
//! reaches the same file through the re-include reads nothing that command
//! does not. Only a regular file below the working directory counts: a
//! hidden directory, a link, or a file the operand screen refuses (`.env`,
//! `.envrc`, `.npmrc`) still holds the search.
use super::{unsafe_search_value, ReadContext, SearchValueRole};
use std::path::Path;

/// Whether `path`, a re-included hidden entry the whitelist walk found, is a
/// regular file whose spelling relative to the working directory clears the
/// `rg` path operand screen.
pub(super) fn searchable_file(path: &Path, context: ReadContext<'_>) -> bool {
    let Some(cwd) = context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok()) else {
        return false;
    };
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_file())
        && path
            .strip_prefix(&cwd)
            .ok()
            .and_then(Path::to_str)
            .is_some_and(|relative| {
                !relative.is_empty()
                    && !unsafe_search_value(SearchValueRole::Path, relative, context)
            })
}

/// The walk-memo marker for a whitelist answer. [`searchable_file`] screens
/// a re-included file by its path below the working directory, so the answer
/// depends on that directory and a segment after `cd` must not reuse it.
pub(super) fn memo_marker(context: ReadContext<'_>) -> String {
    let cwd = context.cwd.and_then(|cwd| std::fs::canonicalize(cwd).ok());
    format!(
        ".rg-whitelist:{}",
        cwd.as_deref().unwrap_or(Path::new("")).display()
    )
}
