//! Python `Path.resolve()` semantics for compound Git inspection.
//!
//! `fs::canonicalize` refuses missing paths; Python's non-strict `resolve`
//! follows symlinks for the prefix that exists, then keeps the remainder and
//! folds `..` lexically. Callers decide what a missing directory means.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};

const MAX_SYMLINK_HOPS: usize = 40;

/// Resolve an absolute path without requiring it to exist. Relative paths,
/// POSIX double-slash roots (a distinct root in Python) and symlink loops are
/// refused rather than guessed at.
pub(crate) fn resolve(path: &Path) -> Option<PathBuf> {
    if !path.is_absolute() || path.to_str().is_some_and(is_double_slash_root) {
        return None;
    }
    let mut pending: VecDeque<OsString> = VecDeque::new();
    let mut resolved = PathBuf::new();
    push_components(&mut pending, path);
    let mut hops = 0;
    while let Some(name) = pending.pop_front() {
        let component = Path::new(&name).components().next();
        match component {
            Some(Component::RootDir | Component::Prefix(_)) => resolved = PathBuf::from(&name),
            Some(Component::ParentDir) => {
                resolved.pop();
            }
            Some(Component::Normal(_)) => {
                let candidate = resolved.join(&name);
                match fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        hops += 1;
                        if hops > MAX_SYMLINK_HOPS {
                            return None;
                        }
                        let target = fs::read_link(&candidate).ok()?;
                        let mut expanded = VecDeque::new();
                        push_components(&mut expanded, &target);
                        expanded.append(&mut pending);
                        pending = expanded;
                    }
                    _ => resolved = candidate,
                }
            }
            Some(Component::CurDir) | None => {}
        }
    }
    Some(resolved)
}

fn is_double_slash_root(text: &str) -> bool {
    cfg!(unix) && text.starts_with("//") && !text.starts_with("///")
}

fn push_components(queue: &mut VecDeque<OsString>, path: &Path) {
    for component in path.components() {
        queue.push_back(component.as_os_str().to_owned());
    }
}

/// `Path.is_relative_to`: component-wise containment, including equality.
pub(crate) fn is_relative_to(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn resolves_missing_tails_and_symlinks_like_python() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("cg-paths-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real/inner")).unwrap();
        symlink("real", root.join("link")).unwrap();
        symlink("link", root.join("chain")).unwrap();
        symlink("loop_b", root.join("loop_a")).unwrap();
        symlink("loop_a", root.join("loop_b")).unwrap();
        assert_eq!(
            resolve(&root.join("chain/inner")).unwrap(),
            root.join("real/inner")
        );
        assert_eq!(
            resolve(&root.join("link/missing/../inner")).unwrap(),
            root.join("real/inner")
        );
        assert_eq!(resolve(&root.join("a/./b//c")).unwrap(), root.join("a/b/c"));
        assert_eq!(
            resolve(&root.join("../..")).unwrap(),
            root.parent().unwrap().parent().unwrap()
        );
        assert_eq!(resolve(Path::new("/")).unwrap(), PathBuf::from("/"));
        assert!(resolve(&root.join("loop_a")).is_none());
        assert!(resolve(Path::new("relative")).is_none());
        assert!(resolve(Path::new("//double")).is_none());
        let _ = fs::remove_dir_all(&root);
    }
}
