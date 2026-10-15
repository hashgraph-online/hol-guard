//! Filesystem probes with `pathlib` semantics for the Codex tool-output review.
//!
//! `Path.resolve(strict=False)` is `posixpath.realpath` followed by a `stat`
//! that turns a symlink loop into `RuntimeError`. `Path.is_symlink`/`is_file`/
//! `is_dir`/`exists` swallow "not there" errors and re-raise the rest; callers
//! that wrapped them in `except OSError` read the `Err` side here.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::codex_output_py::PyPath;

fn as_fs(path: &PyPath) -> String {
    path.to_string()
}

fn ignorable(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
        || error.raw_os_error() == Some(40)
        || error.raw_os_error() == Some(62)
        || error.raw_os_error() == Some(9)
}

/// `Path.is_symlink()`; `Err` is a raised `OSError`.
pub(crate) fn is_symlink(path: &PyPath) -> Result<bool, ()> {
    match fs::symlink_metadata(as_fs(path)) {
        Ok(meta) => Ok(meta.file_type().is_symlink()),
        Err(error) if ignorable(&error) => Ok(false),
        Err(_) => Err(()),
    }
}

fn stat_flag(path: &PyPath, pick: fn(&fs::Metadata) -> bool) -> Result<bool, ()> {
    match fs::metadata(as_fs(path)) {
        Ok(meta) => Ok(pick(&meta)),
        Err(error) if ignorable(&error) => Ok(false),
        Err(_) => Err(()),
    }
}

pub(crate) fn is_file(path: &PyPath) -> Result<bool, ()> {
    stat_flag(path, fs::Metadata::is_file)
}

pub(crate) fn is_dir(path: &PyPath) -> Result<bool, ()> {
    stat_flag(path, fs::Metadata::is_dir)
}

pub(crate) fn exists(path: &PyPath) -> Result<bool, ()> {
    stat_flag(path, |_| true)
}

/// `Path.resolve(strict=False)` for an absolute path. `None` is the
/// `RuntimeError` Python raises for a symlink loop (and for the double-slash
/// root, which Rust does not model).
pub(crate) fn resolve(path: &PyPath) -> Option<PyPath> {
    if !path.is_absolute() || path.root() == "//" {
        return None;
    }
    let mut seen: HashMap<String, Option<String>> = HashMap::new();
    let (joined, ok) = join_realpath(String::new(), &path.to_string(), &mut seen);
    let resolved = PyPath::new(&joined);
    if resolved.root() == "//" {
        return None;
    }
    if !ok {
        return None;
    }
    // Final `p.stat()`: ELOOP is the only error that surfaces.
    match fs::metadata(as_fs(&resolved)) {
        Err(error) if error.raw_os_error() == Some(40) || error.raw_os_error() == Some(62) => None,
        _ => Some(resolved),
    }
}

/// `Path.read_text(encoding="utf-8", errors="ignore")`; `None` is `OSError`.
pub(crate) fn read_text_ignore(path: &PyPath) -> Option<String> {
    let bytes = fs::read(as_fs(path)).ok()?;
    Some(decode_ignore(&bytes))
}

/// `bytes.decode("utf-8", errors="ignore")`.
pub(crate) fn decode_ignore(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        text.push_str(chunk.valid());
    }
    text
}

fn join(base: &str, name: &str) -> String {
    if base.is_empty() || base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

fn split(path: &str) -> (String, String) {
    match path.rfind('/') {
        None => (String::new(), path.to_owned()),
        Some(index) => {
            let mut head = path[..=index].to_owned();
            let tail = path[index + 1..].to_owned();
            if !head.chars().all(|c| c == '/') {
                head = head.trim_end_matches('/').to_owned();
            }
            (head, tail)
        }
    }
}

/// `posixpath._joinrealpath` (non-strict).
fn join_realpath(
    mut path: String,
    rest: &str,
    seen: &mut HashMap<String, Option<String>>,
) -> (String, bool) {
    let mut rest = rest.to_owned();
    if rest.starts_with('/') {
        rest = rest[1..].to_owned();
        path = "/".to_owned();
    }
    while !rest.is_empty() {
        let (name, remainder) = match rest.find('/') {
            Some(index) => (rest[..index].to_owned(), rest[index + 1..].to_owned()),
            None => (rest.clone(), String::new()),
        };
        rest = remainder;
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            if path.is_empty() {
                path = "..".to_owned();
            } else {
                let (head, tail) = split(&path);
                path = head;
                if tail == ".." {
                    path = join(&join(&path, ".."), "..");
                }
            }
            continue;
        }
        let newpath = join(&path, &name);
        let is_link = fs::symlink_metadata(&newpath).is_ok_and(|m| m.file_type().is_symlink());
        if !is_link {
            path = newpath;
            continue;
        }
        match seen.get(&newpath).cloned() {
            Some(Some(resolved)) => {
                path = resolved;
                continue;
            }
            Some(None) => return (join(&newpath, &rest), false),
            None => {}
        }
        seen.insert(newpath.clone(), None);
        let Ok(target) = fs::read_link(Path::new(&newpath)) else {
            return (join(&newpath, &rest), false);
        };
        let (resolved, ok) = join_realpath(path.clone(), &target.to_string_lossy(), seen);
        path = resolved;
        if !ok {
            return (join(&path, &rest), false);
        }
        seen.insert(newpath, Some(path.clone()));
    }
    (path, true)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn resolve_matches_python_for_links_loops_and_missing_tails() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("cg-out-fs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real/inner")).unwrap();
        symlink("real", root.join("link")).unwrap();
        symlink("loop_b", root.join("loop_a")).unwrap();
        symlink("loop_a", root.join("loop_b")).unwrap();
        let at = |tail: &str| PyPath::new(&format!("{}/{tail}", root.display()));
        assert_eq!(
            resolve(&at("link/inner")).unwrap().to_string(),
            format!("{}/real/inner", root.display())
        );
        assert_eq!(
            resolve(&at("link/missing/../inner")).unwrap().to_string(),
            format!("{}/real/inner", root.display())
        );
        assert!(resolve(&at("loop_a")).is_none());
        assert!(resolve(&PyPath::new("relative")).is_none());
        assert_eq!(resolve(&PyPath::new("/")).unwrap().to_string(), "/");
        assert!(is_symlink(&at("link")).unwrap());
        assert!(!is_symlink(&at("nothing")).unwrap());
        assert!(is_dir(&at("link")).unwrap());
        let _ = fs::remove_dir_all(&root);
    }
}
