//! Contained runtime file/path helpers used by shell read assessment.
//! (`sensitive_read_pipeline.py` `:191-322` + `credential_exfiltration.py`
//! `:286-333` + `shell_static_safety._path_text_is_within_root_text` +
//! `request_models._MAX_DECODED_PAYLOAD_BYTES` — verbatim.)
//!
//! Path text follows the host OS exactly as the retired Python's `os.path`
//! did: POSIX compares bytes, Windows compares `normcase`d (lower-cased,
//! backslash) text and resolves roots without the `\\?\` verbatim prefix
//! that `std::fs::canonicalize` adds. Python opened files without
//! `O_NOFOLLOW` on Windows (the flag does not exist there) after a
//! no-follow `stat` regular-file check; this port keeps that.

use std::io::Read;
use std::path::{Path, PathBuf};

pub(crate) const MAX_DECODED_PAYLOAD_BYTES: u64 = 32 * 1024;

/// `os.path.realpath`-shaped canonicalization: on Windows the verbatim
/// `\\?\` prefix `std::fs::canonicalize` adds is removed so the text
/// compares with `normalize_path` output.
fn canonicalize_text(path: &Path) -> std::io::Result<PathBuf> {
    std::fs::canonicalize(path).map(strip_verbatim_prefix)
}

#[cfg(windows)]
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

#[cfg(not(windows))]
fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    path
}

/// `os.path.normcase`: identity on POSIX; lower-case with backslashes on
/// Windows.
#[cfg(windows)]
fn normcase(text: &str) -> String {
    text.replace('/', "\\").to_lowercase()
}

#[cfg(not(windows))]
fn normcase(text: &str) -> String {
    text.to_owned()
}

/// Path components of a normalized absolute path text, in `normcase` form.
fn comparable_segments(text: &str) -> Vec<String> {
    normcase(text)
        .split(std::path::MAIN_SEPARATOR)
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect()
}

fn is_absolute_text(text: &str) -> bool {
    #[cfg(windows)]
    {
        let bytes = text.as_bytes();
        (bytes.len() >= 3 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/'))
            || text.starts_with("\\\\")
    }
    #[cfg(not(windows))]
    {
        text.starts_with('/')
    }
}

/// `Path.is_relative_to` for the host OS: component-wise, case-folded on
/// Windows.
pub(crate) fn path_is_relative_to(path: &Path, root: &Path) -> bool {
    let path_text = path.to_string_lossy();
    let root_text = root.to_string_lossy();
    path_text_is_within_root_text(&path_text, &root_text)
}

/// `_strip_cli_value` (:191-193).
fn strip_cli_value(value: &str) -> String {
    value.trim().trim_matches('\'').trim_matches('"').to_owned()
}

/// `_runtime_read_roots` (:195-210).
pub(crate) fn runtime_read_roots(cwd: Option<&Path>, home_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let fallback_home = || {
        std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
    };
    let home = home_dir.map(Path::to_path_buf).or_else(fallback_home);
    for candidate in [cwd.map(Path::to_path_buf), home].into_iter().flatten() {
        // `Path.resolve(strict=False)` — canonicalize the longest existing
        // prefix and append the remainder lexically.
        let resolved = match weak_canonicalize(&candidate) {
            Some(r) => r,
            None => continue,
        };
        if !roots.contains(&resolved) {
            roots.push(resolved);
        }
    }
    roots
}

/// `Path.resolve(strict=False)` — like `canonicalize` but tolerant of missing
/// trailing components (Rust `canonicalize` errors when any component is
/// missing; walk to the deepest existing prefix).
fn weak_canonicalize(path: &Path) -> Option<PathBuf> {
    match canonicalize_text(path) {
        Ok(p) => Some(p),
        Err(_) => {
            // Resolve the deepest existing ancestor, then append the rest.
            let mut prefix = path.to_path_buf();
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            loop {
                match canonicalize_text(&prefix) {
                    Ok(p) => {
                        let mut out = p;
                        for part in tail.iter().rev() {
                            out.push(part);
                        }
                        return Some(out);
                    }
                    Err(_) => {
                        let name = prefix.file_name()?.to_os_string();
                        tail.push(name);
                        if !prefix.pop() {
                            return None;
                        }
                    }
                }
            }
        }
    }
}

/// `_runtime_read_root_texts` (:226-228).
fn runtime_read_root_texts(roots: &[PathBuf]) -> Vec<String> {
    roots
        .iter()
        .map(|r| {
            canonicalize_text(r)
                .unwrap_or_else(|_| r.clone())
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// `_path_text_is_within_root_text` (shell_static_safety :300-307):
/// `commonpath` of the `normcase`d texts equals the root. Both texts must be
/// absolute; a different Windows drive is a `ValueError`, i.e. not within.
fn path_text_is_within_root_text(path_text: &str, root_text: &str) -> bool {
    if !is_absolute_text(path_text) || !is_absolute_text(root_text) {
        return false;
    }
    let root = comparable_segments(root_text);
    let path = comparable_segments(path_text);
    path.len() >= root.len() && path[..root.len()] == root[..]
}

/// `_runtime_relative_part_is_unsafe` (:221-223 folded) +
/// `_runtime_relative_parts` (:213-220). `os.path.relpath` semantics for an
/// absolute normalized path inside the root: the original-case components
/// after the root's.
fn runtime_relative_parts(path_text: &str, root_text: &str) -> Option<Vec<String>> {
    if !path_text_is_within_root_text(path_text, root_text) {
        return None;
    }
    let root_len = comparable_segments(root_text).len();
    let separators: &[char] = if cfg!(windows) { &['/', '\\'] } else { &['/'] };
    let parts: Vec<String> = path_text
        .split(separators)
        .filter(|segment| !segment.is_empty())
        .skip(root_len)
        .map(str::to_owned)
        .collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|p| p.is_empty() || p == "." || p == ".." || p.contains(separators))
    {
        return None;
    }
    Some(parts)
}

/// `_runtime_entry_name_matches` (:233-247). `normcase` first, then a
/// case-folded name match is confirmed by file identity (`samefile`).
fn runtime_entry_name_matches(
    entry_name: &str,
    requested_name: &str,
    entry_path: &Path,
    requested_path: &Path,
) -> bool {
    if entry_name == requested_name || normcase(entry_name) == normcase(requested_name) {
        return true;
    }
    if entry_name.to_lowercase() != requested_name.to_lowercase() {
        return false;
    }
    same_file(entry_path, requested_path)
}

/// `os.path.samefile`: `(dev, ino)` equality on POSIX.
#[cfg(unix)]
fn same_file(left: &Path, right: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (left.symlink_metadata(), right.symlink_metadata()) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// `os.path.samefile`. The stable std API exposes no Windows file index, so
/// identity is "both resolve to the same existing path"; an unresolvable path
/// is not a match, which only makes the traversal fail closed.
#[cfg(not(unix))]
fn same_file(left: &Path, right: &Path) -> bool {
    match (canonicalize_text(left), canonicalize_text(right)) {
        (Ok(a), Ok(b)) => normcase(&a.to_string_lossy()) == normcase(&b.to_string_lossy()),
        _ => false,
    }
}

/// `_runtime_entry_for_name` (:250-265). Returns the child path on match.
fn runtime_entry_for_name(directory_text: &str, requested_name: &str) -> Option<PathBuf> {
    let requested_path = Path::new(directory_text).join(requested_name);
    let entries = std::fs::read_dir(directory_text).ok()?;
    for entry in entries.flatten() {
        if runtime_entry_name_matches(
            &entry.file_name().to_string_lossy(),
            requested_name,
            &entry.path(),
            &requested_path,
        ) {
            return Some(entry.path());
        }
    }
    None
}

/// `_runtime_file_entry_under_root` (:271-283). Component-by-component
/// traversal that refuses symlink escapes: each intermediate directory is
/// `stat`-ed with `follow_symlinks=False` and re-realpathed inside the root.
fn runtime_file_entry_under_root(path_text: &str, root_text: &str) -> Option<PathBuf> {
    let relative_parts = runtime_relative_parts(path_text, root_text)?;
    let mut current_dir_text = root_text.to_owned();
    for directory_name in &relative_parts[..relative_parts.len() - 1] {
        let directory_entry = runtime_entry_for_name(&current_dir_text, directory_name)?;
        let directory_stat = directory_entry.symlink_metadata().ok()?;
        if !directory_stat.is_dir() {
            return None;
        }
        current_dir_text = canonicalize_text(&directory_entry)
            .ok()?
            .to_string_lossy()
            .into_owned();
        if !path_text_is_within_root_text(&current_dir_text, root_text) {
            return None;
        }
    }
    runtime_entry_for_name(&current_dir_text, relative_parts.last().unwrap())
}

/// `_resolved_runtime_path` (:292-322).
pub(crate) fn resolved_runtime_path(
    value: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    allowed_roots: Option<&[PathBuf]>,
) -> Option<PathBuf> {
    let stripped_value = strip_cli_value(value);
    if stripped_value.is_empty() {
        return None;
    }
    let expanded = crate::home_path_text::expand_home(&stripped_value, home_dir);
    let normalized = crate::home_path_text::normalize_path(&expanded, cwd);
    let candidate = PathBuf::from(&normalized);
    if !candidate.is_absolute() {
        return None;
    }
    let roots = match allowed_roots {
        Some(r) => r.to_vec(),
        None => runtime_read_roots(cwd, home_dir),
    };
    if !roots
        .iter()
        .any(|root| path_is_relative_to(&candidate, root))
    {
        return None;
    }
    for root_text in runtime_read_root_texts(&roots) {
        if let Some(entry) = runtime_file_entry_under_root(&normalized, &root_text) {
            return Some(entry);
        }
    }
    None
}

/// `_read_small_runtime_text_file` (credential_exfiltration :286-333).
/// O_NOFOLLOW open + regular-file + size cap + UTF-8.
pub(crate) fn read_small_runtime_text_file(
    path: &Path,
    allowed_roots: &[PathBuf],
) -> Option<String> {
    let path_text = path.to_string_lossy().into_owned();
    let root_texts = runtime_read_root_texts(allowed_roots);
    if !root_texts
        .iter()
        .any(|root_text| path_text_is_within_root_text(&path_text, root_text))
    {
        return None;
    }
    let runtime_entry = root_texts
        .iter()
        .find_map(|root_text| runtime_file_entry_under_root(&path_text, root_text))?;
    let entry_stat = runtime_entry.symlink_metadata().ok()?;
    if !entry_stat.is_file() || entry_stat.len() > MAX_DECODED_PAYLOAD_BYTES {
        return None;
    }
    let file = open_runtime_file(&runtime_entry)?;
    let stat_result = file.metadata().ok()?;
    if !stat_result.is_file() || stat_result.len() > MAX_DECODED_PAYLOAD_BYTES {
        return None;
    }
    let mut buffer = Vec::new();
    file.take(MAX_DECODED_PAYLOAD_BYTES + 1)
        .read_to_end(&mut buffer)
        .ok()?;
    if buffer.len() as u64 > MAX_DECODED_PAYLOAD_BYTES {
        return None;
    }
    String::from_utf8(buffer).ok()
}

/// `O_RDONLY | O_NOFOLLOW`; `symlink_metadata` above already rejected links.
/// Windows has no `O_NOFOLLOW` (Python used flags `0` there), so the no-follow
/// regular-file check before this open is the guard.
#[cfg(unix)]
fn open_runtime_file(path: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(path)
        .ok()
}

#[cfg(not(unix))]
fn open_runtime_file(path: &Path) -> Option<std::fs::File> {
    std::fs::File::open(path).ok()
}

#[cfg(unix)]
fn libc_o_nofollow() -> i32 {
    // O_NOFOLLOW = 0o200000 on Linux, 0x0100 on macOS (O_NOFOLLOW=0x00000100).
    #[cfg(target_os = "macos")]
    {
        0x0000_0100
    }
    #[cfg(target_os = "linux")]
    {
        0o200000
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        0
    }
}
