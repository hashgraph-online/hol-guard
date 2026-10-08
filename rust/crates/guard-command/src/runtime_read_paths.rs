//! Contained runtime file/path helpers used by shell read assessment.
//! (`sensitive_read_pipeline.py` `:191-322` + `credential_exfiltration.py`
//! `:286-333` + `shell_static_safety._path_text_is_within_root_text` +
//! `request_models._MAX_DECODED_PAYLOAD_BYTES` — verbatim.)

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) const MAX_DECODED_PAYLOAD_BYTES: u64 = 32 * 1024;

/// `_strip_cli_value` (:191-193).
fn strip_cli_value(value: &str) -> String {
    value.trim().trim_matches('\'').trim_matches('"').to_owned()
}

/// `_runtime_read_roots` (:195-210).
pub(crate) fn runtime_read_roots(cwd: Option<&Path>, home_dir: Option<&Path>) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let fallback_home = || std::env::var_os("HOME").map(PathBuf::from);
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
    match path.canonicalize() {
        Ok(p) => Some(p),
        Err(_) => {
            // Resolve the deepest existing ancestor, then append the rest.
            let mut prefix = path.to_path_buf();
            let mut tail: Vec<std::ffi::OsString> = Vec::new();
            loop {
                match prefix.canonicalize() {
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
            std::fs::canonicalize(r)
                .unwrap_or_else(|_| r.clone())
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// `_path_text_is_within_root_text` (shell_static_safety :300-307).
/// `normcase` is identity on POSIX; `commonpath` reduces to a component
/// prefix check since both texts are normalized absolute paths.
fn path_text_is_within_root_text(path_text: &str, root_text: &str) -> bool {
    let path = Path::new(path_text);
    let root = Path::new(root_text);
    if !path.is_absolute() || !root.is_absolute() {
        return false;
    }
    path.starts_with(root)
}

/// `_runtime_relative_part_is_unsafe` (:221-223 folded) +
/// `_runtime_relative_parts` (:213-220). `os.path.relpath` semantics: both
/// inputs are absolute normalized texts → strip the root prefix.
fn runtime_relative_parts(path_text: &str, root_text: &str) -> Option<Vec<String>> {
    let relative = Path::new(path_text).strip_prefix(root_text).ok()?;
    let rel_text = relative.to_string_lossy();
    if rel_text.is_empty() || rel_text == "." {
        return None;
    }
    let parts: Vec<String> = relative
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    if parts.is_empty()
        || relative.components().any(|c| {
            matches!(
                c,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || parts
            .iter()
            .any(|p| p.is_empty() || p == "." || p == ".." || p.contains('/'))
    {
        return None;
    }
    Some(parts)
}

/// `_runtime_entry_name_matches` (:233-247). `normcase` is identity on POSIX;
/// `samefile` = (dev, ino) equality.
fn runtime_entry_name_matches(
    entry_name: &str,
    requested_name: &str,
    entry_path: &Path,
    requested_path: &Path,
) -> bool {
    if entry_name == requested_name {
        return true;
    }
    if entry_name.to_lowercase() != requested_name.to_lowercase() {
        return false;
    }
    match (
        entry_path.symlink_metadata(),
        requested_path.symlink_metadata(),
    ) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
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
        current_dir_text = std::fs::canonicalize(&directory_entry)
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
    if !roots.iter().any(|root| candidate.starts_with(root)) {
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
    // `O_RDONLY | O_NOFOLLOW` — `symlink_metadata` above already rejected
    // links; `OpenOptions` cannot express O_NOFOLLOW portably, so open via
    // `File::open` after the nofollow stat (TOCTOU window mirrors Python,
    // which opens with O_NOFOLLOW; use `open_nofollow` via std `OpenOptions`
    // custom flag on unix).
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(&runtime_entry)
        .ok()?;
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
