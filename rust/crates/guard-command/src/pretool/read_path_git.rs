//! Git metadata an agent may read: ref files, a repository config with no
//! credentials, and a linked worktree's `gitdir` pointer.

use super::{canonical_root, plain};

/// Git ref files in a repository below the verified workspace or user home,
/// or in the common git directory of the linked worktree the session runs in
/// (often a sibling checkout outside both): `.git/HEAD`, `.git/refs/{heads,tags,remotes}/**` and a linked worktree's
/// `.git/worktrees/<name>/HEAD`. They hold a ref name or object id only.
/// `.git/config`, hooks, logs and every other entry stay guarded. A linked
/// worktree's common directory supplies the `.git` marker, so a hidden
/// ancestor of that sibling checkout does not hide it. Home and cwd
/// repositories still use the first hidden component, and every component
/// after the marker must be visible. Only regular files qualify, so a ref
/// directory cannot carry the exception to a search that walks its children.
pub(in crate::pretool) fn git_ref_document(
    canonical: &std::path::Path,
    home_dir: Option<&str>,
    cwd: Option<&str>,
) -> bool {
    let canonical: &std::path::Path = &plain(canonical);
    // `linked_worktree_common_dir` canonicalizes with `std::fs::canonicalize`,
    // which keeps the Windows `\\?\` prefix. The candidate has already been
    // reduced to the plain spelling every other root uses, so the common
    // directory has to be reduced the same way or `starts_with` never matches.
    let common = cwd
        .and_then(|cwd| {
            crate::pretool::worktree_writes::linked_worktree_common_dir(std::path::Path::new(cwd))
        })
        .map(|path| plain(&path));
    let inside_common = common
        .as_ref()
        .is_some_and(|common| canonical.starts_with(common));
    let inside = inside_common
        || [home_dir, cwd]
            .into_iter()
            .flatten()
            .filter_map(canonical_root)
            .any(|root| canonical.starts_with(root));
    let Some(parts) = canonical
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => Some(part.to_str()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let marker = if inside_common {
        common
            .as_ref()
            .and_then(|common| common_git_marker(common, &parts))
    } else {
        parts.iter().position(|part| part.starts_with('.'))
    };
    let Some(marker) = marker else {
        return false;
    };
    let visible = |parts: &[&str]| parts.iter().all(|part| !part.starts_with('.'));
    inside
        && canonical.is_file()
        && parts[marker] == ".git"
        && visible(&parts[marker + 1..])
        && match &parts[marker + 1..] {
            ["HEAD"] => true,
            ["worktrees", _, "HEAD"] => true,
            ["refs", "heads" | "tags" | "remotes", rest @ ..] => !rest.is_empty(),
            _ => false,
        }
}

/// A repository's own `.git/config`: a small regular file of a repository
/// that contains, or sits inside, the working directory, with no credential
/// section, token key, authorization header or URL with userinfo. Anything
/// that looks like a credential keeps the ordinary hidden-path review.
pub(in crate::pretool) fn git_config_document(
    canonical: &std::path::Path,
    cwd: Option<&str>,
) -> bool {
    use std::io::Read;

    let canonical: &std::path::Path = &plain(canonical);

    let Some(root) = canonical
        .parent()
        .filter(|git| git.file_name().is_some_and(|name| name == ".git"))
        .and_then(std::path::Path::parent)
    else {
        return false;
    };
    let Some(workspace) = cwd.and_then(canonical_root) else {
        return false;
    };
    if canonical.file_name().is_none_or(|name| name != "config")
        || !visible_path(root)
        || !(workspace.starts_with(root) || root.starts_with(&workspace))
        || std::fs::symlink_metadata(canonical.parent().unwrap_or(canonical))
            .is_ok_and(|metadata| !metadata.is_dir())
    {
        return false;
    }
    let Ok(metadata) = std::fs::symlink_metadata(canonical) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > 65_536 {
        return false;
    }
    let mut content = String::new();
    std::fs::File::open(canonical)
        .and_then(|file| file.take(65_537).read_to_string(&mut content))
        .is_ok()
        && content.len() <= 65_536
        && crate::pretool::git_config_reads::file_text_free(&content)
}

/// A linked worktree's `.git` pointer file: a small regular file whose only
/// content is `gitdir: <path>`. It names a directory and holds no secret, so
/// reading it is how an agent learns which repository a checkout belongs to.
pub(in crate::pretool) fn worktree_gitfile(canonical: &std::path::Path) -> bool {
    use std::io::Read;

    if canonical.file_name().is_none_or(|name| name != ".git")
        || canonical
            .parent()
            .is_none_or(|parent| !visible_path(parent))
    {
        return false;
    }
    let Ok(metadata) = std::fs::symlink_metadata(canonical) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() > 1024 {
        return false;
    }
    let mut content = String::new();
    if std::fs::File::open(canonical)
        .and_then(|file| file.take(1025).read_to_string(&mut content))
        .is_err()
        || content.len() > 1024
    {
        return false;
    }
    let line = content.strip_suffix('\n').unwrap_or(&content);
    line.strip_prefix("gitdir: ")
        .is_some_and(|path| !path.is_empty() && !path.contains(['\n', '\r', '\0']))
}

/// No component of `path` below the root is hidden.
fn visible_path(path: &std::path::Path) -> bool {
    path.components().all(|component| match component {
        std::path::Component::Normal(part) => !part.to_string_lossy().starts_with('.'),
        _ => true,
    })
}

fn common_git_marker(common: &std::path::Path, parts: &[&str]) -> Option<usize> {
    let count = common
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    (count > 0 && parts.get(count - 1) == Some(&".git")).then_some(count - 1)
}
