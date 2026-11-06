//! OCI bundle path containment (`oci_mount_security.py`): lexical
//! normalisation, bundle-relative resolution that proves a symlink cannot
//! escape the authoritative bundle root, and forbidden host-prefix matching.
//! Filesystem access is read-only (`canonicalize`, `symlink_metadata`,
//! `read_link`); every failure is a refusal, never an allow.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

pub(super) const FORBIDDEN_BIND_SOURCES: [&str; 13] = [
    "/",
    "/etc",
    "/etc/shadow",
    "/etc/passwd",
    "/proc",
    "/sys",
    "/dev",
    "/var/run",
    "/run",
    "/root",
    "/home",
    "/var/lib",
    "/var/log",
];

pub(super) const ROOTFS_LABEL: &str = "OCI rootfs path";
const BIND_LABEL: &str = "OCI bind source";

/// `posixpath.normpath`.
fn normpath(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let absolute = path.starts_with('/');
    let mut kept: Vec<&str> = Vec::new();
    for component in path.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component != ".."
            || (!absolute && kept.is_empty())
            || kept.last().is_some_and(|last| *last == "..")
        {
            kept.push(component);
        } else if !kept.is_empty() {
            kept.pop();
        }
    }
    let joined = kept.join("/");
    let normalized = if absolute {
        format!("/{joined}")
    } else {
        joined
    };
    if normalized.is_empty() {
        ".".to_owned()
    } else {
        normalized
    }
}

/// `normalize_oci_bind_source`: a lexical path and whether a bundle-relative
/// source escapes the bundle.
pub(super) fn normalize_bind_source(source: &str) -> (String, bool) {
    let normalized = normpath(source);
    let escapes = !source.starts_with('/') && (normalized == ".." || normalized.starts_with("../"));
    (normalized, escapes)
}

/// `require_oci_bundle_relative_path`.
pub(super) fn require_bundle_relative(source: &str, label: &str) -> Result<String, String> {
    let (normalized, escapes) = normalize_bind_source(source);
    if source.is_empty() || source.starts_with('/') || normalized == "." || escapes {
        return Err(format!(
            "{label} must be a non-empty bundle-relative path without parent traversal"
        ));
    }
    Ok(normalized)
}

fn posix(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `Path(root).resolve(strict=True)` that must be a directory.
pub(super) fn resolve_root(root: &str) -> Option<PathBuf> {
    let resolved = fs::canonicalize(root).ok()?;
    resolved.is_dir().then_some(resolved)
}

/// `resolve_oci_bundle_path`: prove a bundle-relative path cannot escape.
pub(super) fn resolve_bundle_path(
    source: &str,
    root: Option<&str>,
    label: &str,
    require_directory: bool,
) -> Result<String, String> {
    let normalized = require_bundle_relative(source, label)?;
    let Some(root) = root else {
        return Err(format!(
            "{label} containment requires an authoritative bundle root"
        ));
    };
    let inside = || format!("{label} must resolve inside the authoritative bundle root");
    let resolved_root = resolve_root(root).ok_or_else(inside)?;
    let candidate = fs::canonicalize(resolved_root.join(&normalized)).map_err(|_| inside())?;
    if !candidate.starts_with(&resolved_root) {
        return Err(inside());
    }
    if require_directory && !candidate.is_dir() {
        return Err(format!("{label} must resolve to a directory"));
    }
    Ok(posix(&candidate))
}

/// `resolve_oci_bind_source`.
pub(super) fn resolve_bind_source(source: &str, root: Option<&str>) -> Result<String, String> {
    let (normalized, escapes) = normalize_bind_source(source);
    if source.is_empty() || escapes {
        return Err("OCI bind source must not traverse outside the bundle".to_owned());
    }
    if source.starts_with('/') {
        let contained =
            "absolute OCI bind source must resolve inside the authoritative bundle root";
        let Some(root) = root else {
            return Err(
                "absolute OCI bind source containment requires an authoritative bundle root"
                    .to_owned(),
            );
        };
        let resolved_root = resolve_root(root).ok_or_else(|| contained.to_owned())?;
        let resolved = fs::canonicalize(&normalized).map_err(|_| contained.to_owned())?;
        if !resolved.starts_with(&resolved_root) {
            return Err(contained.to_owned());
        }
        return Ok(posix(&resolved));
    }
    resolve_bundle_path(&normalized, root, BIND_LABEL, false)
}

/// `Path(path).resolve(strict=False)` for an absolute path (CPython 3.13+
/// `posixpath.realpath`): symlinks are followed as far as they exist, the
/// unresolvable remainder is kept lexically, and a loop stops resolving.
pub(super) fn resolve_lenient(path: &str) -> String {
    let mut seen: HashMap<String, Option<String>> = HashMap::new();
    let mut rest: Vec<Option<String>> = path
        .split('/')
        .rev()
        .map(|part| Some(part.to_owned()))
        .collect();
    let mut resolved = "/".to_owned();
    while let Some(entry) = rest.pop() {
        let Some(name) = entry else {
            if let Some(Some(link)) = rest.pop() {
                seen.insert(link, Some(resolved.clone()));
            }
            continue;
        };
        if name.is_empty() || name == "." {
            continue;
        }
        if name == ".." {
            resolved = match resolved.rfind('/') {
                Some(0) | None => "/".to_owned(),
                Some(index) => resolved[..index].to_owned(),
            };
            continue;
        }
        let candidate = if resolved == "/" {
            format!("/{name}")
        } else {
            format!("{resolved}/{name}")
        };
        let Ok(metadata) = fs::symlink_metadata(&candidate) else {
            resolved = candidate;
            continue;
        };
        if !metadata.file_type().is_symlink() {
            resolved = candidate;
            continue;
        }
        if let Some(cached) = seen.get(&candidate) {
            // A cached target is reused; an unresolved entry is a loop.
            resolved = cached.clone().unwrap_or(candidate);
            continue;
        }
        let Ok(target) = fs::read_link(&candidate) else {
            resolved = candidate;
            continue;
        };
        let target = target.to_string_lossy().into_owned();
        if target.starts_with('/') {
            resolved = "/".to_owned();
        }
        seen.insert(candidate.clone(), None);
        rest.push(Some(candidate));
        rest.push(None);
        rest.extend(target.split('/').rev().map(|part| Some(part.to_owned())));
    }
    resolved
}

/// `match_forbidden_oci_path`: the configured prefix matching a lexical or
/// resolved path.
pub(super) fn match_forbidden<'a>(source: &str, forbidden: &[&'a str]) -> Option<&'a str> {
    let (normalized, _) = normalize_bind_source(source);
    let mut candidates = vec![normalized.clone()];
    if normalized.starts_with('/') {
        candidates.push(resolve_lenient(&normalized));
    }
    let mut ordered: Vec<&'a str> = forbidden.to_vec();
    ordered.sort_unstable();
    ordered.into_iter().find(|prefix_source| {
        let prefixes = [(*prefix_source).to_owned(), resolve_lenient(prefix_source)];
        candidates.iter().any(|candidate| {
            prefixes.iter().any(|prefix| {
                candidate == prefix
                    || (prefix != "/"
                        && candidate.starts_with(&format!("{}/", prefix.trim_end_matches('/'))))
            })
        })
    })
}

/// `is_oci_host_path_mount`.
pub(super) fn is_host_path_mount(mount_type: &str, options: &[String], source: &str) -> bool {
    let bind_option = options
        .iter()
        .any(|option| option == "bind" || option == "rbind");
    mount_type == "bind"
        || bind_option
        || (matches!(mount_type, "" | "none")
            && (source.starts_with('/') || source.starts_with("./") || source.starts_with("../")))
}
