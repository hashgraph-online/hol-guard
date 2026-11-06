//! Why a direct read of one path stays under review, in words about a read.
//!
//! The shared next-step text for `native_file_read_review` explains how to
//! narrow a search. A `read` of a single path is not a search, so it carries
//! its own explanation instead: which kind of path Guard holds and what to
//! read in its place. Only the path the agent already sent is repeated, and
//! no file is opened to build the text.

use super::omp::OmpContext;

/// Start of the review text of a direct read. The next-step text that follows
/// a review looks for it and leaves its search advice out.
pub(super) const READ_REVIEW_PREFIX: &str = "HOL Guard requires review before this file read";

const LONGEST_SHOWN_PATH: usize = 512;

/// The review text for a `read` of one path, or `None` for any other call.
pub(super) fn read_review_reason(
    signals: &super::extract::GenericSignals,
    context: &OmpContext<'_>,
) -> Option<String> {
    if context.event != "PreToolUse"
        || !matches!(signals.tool_name.as_deref(), Some("read" | "Read"))
        || signals.path_values.len() != 1
    {
        return None;
    }
    let path = signals.path_values[0].trim();
    let shown = if path.len() <= LONGEST_SHOWN_PATH
        && !path.contains('`')
        && !path.chars().any(char::is_control)
    {
        format!("`{path}`")
    } else {
        "this path".to_owned()
    };
    let resolved = resolve(path, context.path.home_dir, context.path.cwd);
    let checked = resolved.as_deref().unwrap_or(std::path::Path::new(path));
    let note = if guard_secure_fs::sensitive_path_family(checked).is_some() {
        format!(
            "{shown} is a credential or secret file, so Guard holds a read of it. Read a different file, or leave it for the user."
        )
    } else if guard_secure_fs::credential_named_path(checked) {
        format!(
            "{shown} is named like a credential store, so Guard holds a read of it. Read a different file, or leave it for the user."
        )
    } else {
        format!(
            "Guard could not verify {shown} as a path that is safe to read. Check that it is a regular file or folder inside the project or the home folder, or leave it for the user."
        )
    };
    Some(format!("{READ_REVIEW_PREFIX} can execute. {note}"))
}

fn resolve(path: &str, home: Option<&str>, cwd: Option<&str>) -> Option<std::path::PathBuf> {
    let expanded = super::super::read_paths::expand_home_read_path(path, home)
        .unwrap_or_else(|| path.to_owned());
    let expanded = std::path::Path::new(&expanded);
    let candidate = if expanded.is_absolute() {
        expanded.to_path_buf()
    } else {
        std::path::Path::new(cwd?).join(expanded)
    };
    std::fs::canonicalize(candidate).ok()
}
