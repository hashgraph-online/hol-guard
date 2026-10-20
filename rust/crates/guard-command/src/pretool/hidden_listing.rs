//! `ls` of a hidden directory or file inside a repository work tree, such as a deploy
//! lock directory or the `.git` marker an agent probes for. Listing returns
//! names, not file content. Credential stores and agent state keep their
//! guard, and the repository root must clear every sensitive-path screen.

use std::path::{Component, Path};

#[path = "home_hidden_listing.rs"]
mod home;
pub(in crate::pretool) use home::{
    home_hidden_content_read, home_hidden_directory, home_hidden_tool_directory,
    resolved_home_hidden_content_read,
};

/// Agent state and tool trees whose entry names reveal agent state inside a
/// repository. Credential stores and harness homes come from the shared home
/// lists.
const AGENT_STATE_NAMES: [&str; 5] = [".agent", ".agents", ".config", ".local", ".npm"];

fn guarded_hidden_name(name: &str) -> bool {
    AGENT_STATE_NAMES.contains(&name)
        || home::CREDENTIAL_STORE_NAMES.contains(&name)
        || home::HARNESS_HOME_NAMES.contains(&name)
}

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
    // the outermost; the work tree that must carry `.git` holds it.
    let Some(repository) = canonical
        .ancestors()
        .filter(|ancestor| {
            ancestor
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        })
        .last()
        .and_then(|outermost| enclosing_work_tree(outermost, home_dir))
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
        !guarded_hidden_name(&name) && !name.starts_with(".env")
    }) && std::fs::symlink_metadata(repository.join(".git")).is_ok()
        && guard_secure_fs::sensitive_path_family(&canonical).is_none()
        && !guard_secure_fs::credential_named_path(&canonical)
        && super::resolved_path_allowed(repository, home_dir, cwd)
}

/// The work tree holding the outermost hidden component: its parent when that
/// carries `.git`, as for `app/.deploy.lock.d`, or else the nearest
/// non-hidden ancestor strictly below home that does, as for an installed
/// tool shim directory such as `app/node_modules/.bin`. The search never
/// reaches home itself or leaves it, so a hidden directory in a plain folder
/// stays guarded.
fn enclosing_work_tree<'a>(outermost: &'a Path, home_dir: Option<&str>) -> Option<&'a Path> {
    let parent = outermost.parent()?;
    if work_tree_marker(parent) {
        return Some(parent);
    }
    let home = std::fs::canonicalize(home_dir?).ok()?;
    parent
        .ancestors()
        .skip(1)
        .take_while(|ancestor| ancestor.starts_with(&home) && *ancestor != home.as_path())
        .find(|ancestor| work_tree_marker(ancestor))
}

fn work_tree_marker(directory: &Path) -> bool {
    std::fs::symlink_metadata(directory.join(".git")).is_ok()
}
