//! Path helpers for AIBOM discovery, mirroring the `pathlib` and
//! `path_support` semantics the discovery rules were written against:
//! lexical normalization, non-strict `resolve`, containment, and sorted
//! non-recursive/recursive matching that never follows directory links.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

/// `Path(value)`: collapses empty and `.` components, keeps `..`.
pub(crate) fn py_path(value: &str) -> PathBuf {
    let mut out = PathBuf::new();
    for component in Path::new(value).components() {
        if !matches!(component, Component::CurDir) {
            out.push(component.as_os_str());
        }
    }
    out
}

/// `base / value`: an absolute `value` replaces the base, as in `pathlib`.
pub(crate) fn py_join(base: &Path, value: &str) -> PathBuf {
    if value.starts_with('/') {
        return py_path(value);
    }
    let mut out = PathBuf::new();
    for component in base.components().chain(Path::new(value).components()) {
        if !matches!(component, Component::CurDir) {
            out.push(component.as_os_str());
        }
    }
    out
}

/// Non-strict `Path.resolve()`, shared with the compound-git resolver so the
/// two cannot diverge: symlinks resolve over the existing prefix, the remainder
/// is appended lexically, and the result never carries a Windows verbatim
/// prefix. A link loop or a relative input is an error, never a partial answer.
pub(crate) fn resolve(path: &Path) -> Result<PathBuf, ()> {
    super::compound_git_paths::resolve(path).ok_or(())
}

pub(crate) fn is_file(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
}

pub(crate) fn is_dir(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

pub(crate) fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

pub(crate) fn exists(path: &Path) -> bool {
    fs::metadata(path).is_ok()
}

/// `resolves_within_root`.
pub(crate) fn resolves_within_root(root: &Path, candidate: &Path, require_exists: bool) -> bool {
    let (Ok(resolved_root), Ok(resolved)) = (resolve(root), resolve(candidate)) else {
        return false;
    };
    // Containment first: `exists` stats the resolved path, so it runs only for
    // a candidate already inside the workspace.
    if !resolved.starts_with(&resolved_root) {
        return false;
    }
    !require_exists || exists(&resolved)
}

/// `is_safe_relative_path(root, value, require_exists=False)`.
pub(crate) fn is_safe_relative_path(root: &Path, value: &str) -> bool {
    if value.starts_with('/') {
        return false;
    }
    resolves_within_root(root, &py_join(root, value), false)
}

/// SHA-256 of the full file bytes; `None` when the file cannot be read.
pub(crate) fn file_content_hash(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 65_536];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => digest.update(&chunk[..count]),
            Err(_) => return None,
        }
    }
    Some(hex::encode(digest.finalize()))
}

pub(crate) fn file_name_string(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `Path.stem` for a name that is known to carry a suffix.
pub(crate) fn stem(name: &str) -> &str {
    match name.rfind('.') {
        Some(index) if index > 0 => &name[..index],
        _ => name,
    }
}

fn component_names(path: &Path, base: &Path) -> Vec<String> {
    path.strip_prefix(base)
        .unwrap_or(path)
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect()
}

pub(crate) const ERR_NON_UTF8: &str = "native_runner_authority_aibom_non_utf8_path";

/// A directory entry name, or a typed refusal for a non-UTF-8 name that could
/// hide matching content: it can never be carried in JSON, and silently
/// dropping it would omit content from inventory. A name ending in `suffix` is
/// always refused; with `descend`, a real directory is refused too because a
/// recursive walk would have to enter it. Any other non-UTF-8 entry (an image,
/// a binary) cannot match and is skipped.
fn entry_name(
    entry: &fs::DirEntry,
    suffix: &str,
    descend: bool,
) -> Result<Option<String>, &'static str> {
    match entry.file_name().into_string() {
        Ok(name) => Ok(Some(name)),
        Err(raw) => {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt;
                let is_real_dir = descend && entry.file_type().is_ok_and(|kind| kind.is_dir());
                if is_real_dir || raw.as_bytes().ends_with(suffix.as_bytes()) {
                    return Err(ERR_NON_UTF8);
                }
            }
            #[cfg(not(unix))]
            let _ = (raw, suffix, descend, entry);
            Ok(None)
        }
    }
}

/// `iter_safe_matching_files(root, base_dir, "*<suffix>")`: direct children
/// ending in `suffix`, sorted by name, regular files that stay inside `root`.
pub(crate) fn safe_matching_files(
    root: &Path,
    base_dir: &Path,
    suffix: &str,
) -> Result<Vec<PathBuf>, &'static str> {
    if resolve(root).is_err() || !is_dir(base_dir) || !resolves_within_root(root, base_dir, true) {
        return Ok(Vec::new());
    }
    let Ok(entries) = fs::read_dir(base_dir) else {
        return Ok(Vec::new());
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        if let Some(name) = entry_name(&entry, suffix, false)? {
            if name.ends_with(suffix) {
                names.push(name);
            }
        }
    }
    names.sort();
    Ok(names
        .into_iter()
        .map(|name| base_dir.join(name))
        .filter(|candidate| is_file(candidate) && resolves_within_root(root, candidate, true))
        .collect())
}

/// `sorted(base_dir.rglob("*.md"))` filtered to unlinked regular files inside
/// `root`. Directory links are never followed; unreadable directories are
/// skipped, as `pathlib` does.
pub(crate) fn recursive_markdown_files(
    root: &Path,
    base_dir: &Path,
) -> Result<Vec<PathBuf>, &'static str> {
    let mut found: Vec<(Vec<String>, PathBuf)> = Vec::new();
    let mut pending = vec![base_dir.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let Some(name) = entry_name(&entry, ".md", true)? else {
                continue;
            };
            let path = directory.join(&name);
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                pending.push(path.clone());
            }
            if name.ends_with(".md") {
                found.push((component_names(&path, base_dir), path));
            }
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found
        .into_iter()
        .map(|(_, path)| path)
        .filter(|candidate| {
            is_file(candidate)
                && !is_symlink(candidate)
                && resolves_within_root(root, candidate, true)
        })
        .collect())
}

pub(crate) const DOC_DIRECTORY_ROLES: [(&str, &str); 7] = [
    ("design", "design_md"),
    ("product", "product_md"),
    ("standards", "standards_md"),
    ("policy", "policy_md"),
    ("policies", "policy_md"),
    ("security", "security_md"),
    ("roadmap", "roadmap_md"),
];

/// `instruction_role_for_path`.
pub(crate) fn instruction_role_for_path(path: &Path) -> Option<&'static str> {
    let name = file_name_string(path).to_lowercase();
    let by_name = match name.as_str() {
        "agents.md" => Some("agents_md"),
        "claude.md" => Some("claude_md"),
        "design.md" => Some("design_md"),
        "product.md" => Some("product_md"),
        "roadmap.md" => Some("roadmap_md"),
        "security.md" => Some("security_md"),
        "policy.md" | "policies.md" => Some("policy_md"),
        "standards.md" => Some("standards_md"),
        "mcp.json" => Some("mcp_json"),
        _ => None,
    };
    if by_name.is_some() {
        return by_name;
    }
    let raw_name = file_name_string(path);
    let suffix = match raw_name.rfind('.') {
        Some(index) if index > 0 && index + 1 < raw_name.len() => raw_name[index..].to_lowercase(),
        _ => String::new(),
    };
    if suffix != ".md" && suffix != ".mdc" {
        return None;
    }
    let parts: Vec<String> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    for (index, part) in parts.iter().enumerate() {
        let Some(next) = parts.get(index + 1) else {
            continue;
        };
        if part == ".cursor" && next == "rules" {
            return Some("cursor_rules");
        }
        if part == "docs" {
            let child = next.to_lowercase();
            if let Some((_, role)) = DOC_DIRECTORY_ROLES
                .iter()
                .find(|(directory, _)| *directory == child)
            {
                return Some(role);
            }
        }
    }
    None
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn non_utf8_names_only_refuse_when_they_could_match() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("aibom-paths-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("docs")).unwrap();
        fs::write(root.join("docs/a.md"), "a").unwrap();
        fs::write(
            root.join("docs").join(OsStr::from_bytes(b"img\xff.png")),
            "x",
        )
        .unwrap();
        let found = recursive_markdown_files(&root, &root.join("docs")).unwrap();
        assert_eq!(found, vec![root.join("docs/a.md")]);
        fs::write(
            root.join("docs").join(OsStr::from_bytes(b"bad\xff.md")),
            "x",
        )
        .unwrap();
        assert_eq!(
            recursive_markdown_files(&root, &root.join("docs")),
            Err(ERR_NON_UTF8)
        );
        let _ = fs::remove_dir_all(&root);
    }
}
