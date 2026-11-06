//! Repository metadata reached by a recursive `grep`.
//!
//! `grep -r` has no notion of a repository, so a search rooted at a checkout
//! also reads its `.git` entry. Refusing that entry outright sends nearly every
//! repository-wide search to review. What `.git` holds is mostly history the
//! agent can already print with `git log` or `git show`; the parts that can
//! carry a credential are the configuration files, where remote URLs,
//! `http.extraHeader` values and credential sections live, and add-on key
//! stores such as git-crypt's.
//!
//! A `.git` file (a linked worktree or submodule pointer) is allowed only when
//! it holds a single `gitdir:` line. A `.git` directory is walked by metadata
//! like any tree, never following links. Every configuration file in it, and
//! every legacy remote definition under `remotes/` or `branches/`, is read,
//! bounded, and must carry no credential marker; any key store, hidden name,
//! secret extension or credential name sends the search to review.
use std::io::Read;
use std::path::Path;

const MAX_ENTRIES: usize = 20_000;
const MAX_DEPTH: usize = 16;
const MAX_POINTER_BYTES: u64 = 4 * 1024;
const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const CONFIG_NAMES: &[&str] = &["config", "config.worktree"];
/// Directories whose files hold legacy remote URLs.
const REMOTE_DIRECTORIES: &[&str] = &["remotes", "branches"];
const KEY_STORES: &[&str] = &["git-crypt", "credentials", "credential"];
/// Lowercase substrings that mark a credential in Git configuration.
const CREDENTIAL_MARKERS: &[&str] = &[
    "extraheader",
    "[credential",
    "password",
    "passwd",
    "token",
    "oauth",
    "authorization",
    "bearer",
    "secret",
];

/// True when a recursive `grep` may read the `.git` entry at `path`.
pub(in crate::pretool) fn safe_git_entry(path: &Path, metadata: &std::fs::Metadata) -> bool {
    if metadata.is_file() {
        return gitdir_pointer(path, metadata);
    }
    metadata.is_dir() && safe_git_directory(path)
}

/// A linked worktree or submodule `.git` file: one `gitdir: <path>` line.
fn gitdir_pointer(path: &Path, metadata: &std::fs::Metadata) -> bool {
    let Some(text) = bounded_text(path, metadata, MAX_POINTER_BYTES) else {
        return false;
    };
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let pointer = lines.next().and_then(|line| line.strip_prefix("gitdir: "));
    pointer.is_some_and(|target| !target.trim().is_empty()) && lines.next().is_none()
}

fn safe_git_directory(root: &Path) -> bool {
    let mut pending = vec![(root.to_path_buf(), 0_usize)];
    let mut inspected = 0_usize;
    while let Some((path, depth)) = pending.pop() {
        inspected += 1;
        if inspected > MAX_ENTRIES || depth > MAX_DEPTH {
            return false;
        }
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            return false;
        };
        if depth > 0 && !safe_git_descendant(&path, root, &metadata) {
            return false;
        }
        if metadata.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                return false;
            };
            for entry in entries {
                let Ok(entry) = entry else { return false };
                if pending.len() + inspected >= MAX_ENTRIES {
                    return false;
                }
                pending.push((entry.path(), depth + 1));
            }
        }
    }
    true
}

fn safe_git_descendant(path: &Path, root: &Path, metadata: &std::fs::Metadata) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lowered = name.to_ascii_lowercase();
    if KEY_STORES.contains(&lowered.as_str()) {
        return false;
    }
    if metadata.is_dir() {
        return super::tree::descendant_allowed(path, root, false);
    }
    if !metadata.is_file() {
        return false;
    }
    let in_remote_directory = path
        .parent()
        .filter(|parent| parent.parent() == Some(root))
        .and_then(|parent| parent.file_name())
        .and_then(|parent| parent.to_str())
        // Default macOS volumes are case-insensitive, so `.git/Remotes`
        // resolves like `.git/remotes`.
        .is_some_and(|parent| REMOTE_DIRECTORIES.contains(&parent.to_ascii_lowercase().as_str()));
    if CONFIG_NAMES.contains(&lowered.as_str()) || in_remote_directory {
        return config_without_credentials(path, metadata);
    }
    super::tree::descendant_allowed(path, root, true)
}

fn bounded_text(path: &Path, metadata: &std::fs::Metadata, limit: u64) -> Option<String> {
    if metadata.len() > limit {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text).ok()?;
    (text.len() as u64 <= limit).then_some(text)
}

fn config_without_credentials(path: &Path, metadata: &std::fs::Metadata) -> bool {
    let Some(text) = bounded_text(path, metadata, MAX_CONFIG_BYTES) else {
        return false;
    };
    let text = text.to_ascii_lowercase();
    !CREDENTIAL_MARKERS
        .iter()
        .any(|marker| text.contains(marker))
        && !text.contains("[include")
        && !text.contains("[includeif")
        && !url_with_userinfo(&text)
}

/// A remote URL that embeds a secret: any password (`user:pw@`), or any
/// user name over HTTP, where a token is commonly passed as the user name.
/// `ssh://git@host` names only the SSH login and is not a credential.
fn url_with_userinfo(text: &str) -> bool {
    text.match_indices("://").any(|(index, _)| {
        let scheme = text[..index]
            .rsplit(|character: char| {
                !(character.is_ascii_alphanumeric() || "+.-".contains(character))
            })
            .next()
            .unwrap_or_default();
        let authority = text[index + 3..]
            .split(|character: char| character == '/' || character.is_whitespace())
            .next()
            .unwrap_or_default();
        authority.rsplit_once('@').is_some_and(|(userinfo, _)| {
            userinfo.contains(':') || !matches!(scheme, "ssh" | "git+ssh" | "ssh+git")
        })
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn userinfo_urls_are_detected() {
        for (text, expected) in [
            ("url = https://github.com/example/repo.git", false),
            ("url = git@github.com:example/repo.git", false),
            ("url = ssh://git@github.com/example/repo.git", false),
            ("url = ssh://git:pw@github.com/example/repo.git", true),
            ("url = https://user:pw@example.com/repo", true),
            ("url = https://abc123@example.com/repo", true),
        ] {
            assert_eq!(super::url_with_userinfo(text), expected, "{text}");
        }
    }
}
