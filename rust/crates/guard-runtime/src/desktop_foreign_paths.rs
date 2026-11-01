//! The `pathlib` and `os.path` behaviour the foreign-install inventory
//! compares paths with, and the bounded reads it makes of a bin entry.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const CONTENT_SCAN_LIMIT: u64 = 1024 * 1024;
const MAX_SYMLINK_FOLLOWS: usize = 40;

/// `Path.resolve(strict=False)`: links in the existing prefix followed,
/// the rest kept as written.
pub(super) fn resolve(cwd: &Path, path: &Path) -> PathBuf {
    let mut pending = Vec::new();
    push_parts(&absolute(cwd, path), &mut pending);
    let mut resolved = PathBuf::new();
    let mut follows = 0;
    while let Some(part) = pending.pop() {
        match part {
            Part::Base(base) => resolved = base,
            Part::Parent => {
                resolved.pop();
            }
            Part::Name(name) => {
                let candidate = resolved.join(&name);
                match fs::read_link(&candidate) {
                    Ok(target) if follows < MAX_SYMLINK_FOLLOWS => {
                        follows += 1;
                        push_parts(&target, &mut pending);
                    }
                    _ => resolved = candidate,
                }
            }
        }
    }
    resolved
}

fn absolute(cwd: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

/// One step of a path still to resolve, kept on a stack in reverse.
enum Part {
    Base(PathBuf),
    Parent,
    Name(std::ffi::OsString),
}

fn push_parts(path: &Path, pending: &mut Vec<Part>) {
    let mut base = PathBuf::new();
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => base.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => parts.push(Part::Parent),
            Component::Normal(name) => parts.push(Part::Name(name.to_owned())),
        }
    }
    if !base.as_os_str().is_empty() {
        parts.insert(0, Part::Base(base));
    }
    pending.extend(parts.into_iter().rev());
}

/// `Path(value)`: repeated separators, `.` parts and a trailing separator
/// dropped.
pub(super) fn pure(value: &str) -> PathBuf {
    let path: PathBuf = Path::new(value)
        .components()
        .filter(|component| *component != Component::CurDir)
        .collect();
    if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path
    }
}

/// `os.path.normpath`: `..` folded lexically, so a target whose venv is gone
/// still names it.
pub(super) fn normpath(path: &Path) -> PathBuf {
    let mut parts: Vec<Component<'_>> = Vec::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match parts.last() {
                Some(Component::Normal(_)) => {
                    parts.pop();
                }
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => parts.push(component),
            },
            _ => parts.push(component),
        }
    }
    if parts.is_empty() {
        PathBuf::from(".")
    } else {
        parts.iter().collect()
    }
}

/// `_link_target`: where a link points, or the entry itself.
pub(super) fn link_target(entry: &Path) -> PathBuf {
    let Ok(target) = fs::read_link(entry) else {
        return entry.to_path_buf();
    };
    if target.is_absolute() {
        normpath(&target)
    } else {
        normpath(&entry.parent().unwrap_or(entry).join(target))
    }
}

/// `_head`: the first MiB of a regular file, or nothing.
pub(super) fn head(path: &Path) -> Vec<u8> {
    let mut content = Vec::new();
    if is_file(path) {
        if let Ok(file) = File::open(path) {
            if file
                .take(CONTENT_SCAN_LIMIT)
                .read_to_end(&mut content)
                .is_err()
            {
                content.clear();
            }
        }
    }
    content
}

pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// `PurePath.is_relative_to`, case-blind where `pathlib` is.
pub(super) fn within(path: &Path, root: &Path) -> bool {
    if cfg!(windows) {
        PathBuf::from(path_key(path)).starts_with(path_key(root))
    } else {
        path.starts_with(root)
    }
}

pub(super) fn path_key(path: &Path) -> String {
    let text = path.to_string_lossy();
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text.into_owned()
    }
}

pub(super) fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

pub(super) fn is_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

pub(super) fn is_dir(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

pub(super) fn exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}
