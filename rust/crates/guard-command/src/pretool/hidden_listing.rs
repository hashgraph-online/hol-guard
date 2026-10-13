//! `ls` of a hidden directory or file inside a repository work tree, such as a deploy
//! lock directory or the `.git` marker an agent probes for. Listing returns
//! names, not file content. Credential stores and agent state keep their
//! guard, and the repository root must clear every sensitive-path screen.

use std::path::{Component, Path};

/// Hidden names whose entry names alone reveal credential or agent state.
const GUARDED_HIDDEN_NAMES: [&str; 18] = [
    ".agent",
    ".agents",
    ".aws",
    ".azure",
    ".claude",
    ".codex",
    ".config",
    ".docker",
    ".gcloud",
    ".gnupg",
    ".hol-guard",
    ".kube",
    ".local",
    ".mozilla",
    ".npm",
    ".password-store",
    ".ssh",
    ".terraform",
];

/// Whether `value` names an existing directory below a hidden component that
/// sits inside a repository work tree the session may already read.
pub(in crate::pretool) fn repository_hidden_directory(
    value: &str,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let path = value.trim();
    if path.is_empty()
        || path.len() > 4096
        || path.contains([
            '$', '`', '|', ';', '&', '<', '>', '\n', '\r', '\0', '*', '?', '{', '}', '[', ']',
        ])
        || path.split(['/', '\\']).any(|part| part == "..")
    {
        return false;
    }
    let expanded = super::expand_home_read_path(path, home_dir).unwrap_or_else(|| path.to_owned());
    let expanded = Path::new(&expanded);
    let candidate = if expanded.is_absolute() {
        expanded.to_path_buf()
    } else if let Some(root) = cwd.filter(|root| Path::new(root).is_absolute()) {
        Path::new(root).join(expanded)
    } else {
        return false;
    };
    let Ok(canonical) = std::fs::canonicalize(candidate) else {
        return false;
    };
    // A listing prints names and metadata only, so an existing regular file
    // is as safe as a directory under the same screens.
    if !canonical.is_dir() && !canonical.is_file() {
        return false;
    }
    // Ancestors run from the deepest path up, so the last hidden one found is
    // the outermost; its parent is the work tree that must carry `.git`.
    let Some(repository) = canonical
        .ancestors()
        .filter(|ancestor| {
            ancestor
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        })
        .last()
        .and_then(Path::parent)
    else {
        return false;
    };
    let Ok(below) = canonical.strip_prefix(repository) else {
        return false;
    };
    below.components().all(|component| {
        let Component::Normal(name) = component else {
            return false;
        };
        let name = name.to_string_lossy().to_ascii_lowercase();
        !GUARDED_HIDDEN_NAMES.contains(&name.as_str()) && !name.starts_with(".env")
    }) && std::fs::symlink_metadata(repository.join(".git")).is_ok()
        && guard_secure_fs::sensitive_path_family(&canonical).is_none()
        && !guard_secure_fs::credential_named_path(&canonical)
        && super::resolved_path_allowed(repository, home_dir, cwd)
}
