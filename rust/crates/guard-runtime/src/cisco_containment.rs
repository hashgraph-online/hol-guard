//! Filesystem containment and revalidation for Cisco preflight scans.
//!
//! The resident resolves every path itself, so the scan root it hands back is
//! the one it verified: the target must resolve to a readable regular file
//! inside an approved root, and the derived scan root must stay inside that
//! same root. Every validated target is revalidated immediately after.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ApprovedRoot {
    pub(crate) path: PathBuf,
    pub(crate) label: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Validated {
    pub(crate) path: Option<PathBuf>,
    pub(crate) scan_root: PathBuf,
    pub(crate) approved_root: ApprovedRoot,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Contain {
    pub(crate) reason: &'static str,
    pub(crate) label: String,
}

const SELECTED: &str = "selected-workspace";

fn fail(reason: &'static str, label: &str) -> Contain {
    Contain {
        reason,
        label: label.to_owned(),
    }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() {
        0o755
    } else {
        0o644
    }
}

const READ_BITS: u32 = 0o444;
const EXEC_BITS: u32 = 0o111;

#[cfg(unix)]
fn accessible(path: &Path, exec: bool) -> bool {
    use nix::unistd::{access, AccessFlags};
    let flags = AccessFlags::R_OK
        | if exec {
            AccessFlags::X_OK
        } else {
            AccessFlags::empty()
        };
    access(path, flags).is_ok()
}

#[cfg(not(unix))]
fn accessible(path: &Path, exec: bool) -> bool {
    if exec {
        std::fs::read_dir(path).is_ok()
    } else {
        std::fs::File::open(path).is_ok()
    }
}

fn expand(value: &str, home: Option<&str>) -> PathBuf {
    match (value, home) {
        ("~", Some(home)) => PathBuf::from(home),
        (_, Some(home)) if value.starts_with("~/") => Path::new(home).join(&value[2..]),
        _ => PathBuf::from(value),
    }
}

fn resolve(path: &Path) -> Option<(PathBuf, std::fs::Metadata)> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let meta = std::fs::metadata(&canonical).ok()?;
    #[cfg(windows)]
    let canonical = {
        let text = canonical.to_string_lossy();
        match text.strip_prefix(r"\\?\") {
            Some(stripped) => PathBuf::from(stripped),
            None => canonical,
        }
    };
    Some((canonical, meta))
}

fn readable_directory(
    value: &str,
    base: &Path,
    home: Option<&str>,
    label: &str,
) -> Result<PathBuf, Contain> {
    let expanded = expand(value, home);
    let candidate = if expanded.is_absolute() {
        expanded
    } else {
        base.join(expanded)
    };
    let (canonical, meta) =
        resolve(&candidate).ok_or_else(|| fail("approved_root_unresolved", label))?;
    let mode = mode_of(&meta);
    if !meta.is_dir()
        || mode & READ_BITS == 0
        || mode & EXEC_BITS == 0
        || !accessible(&canonical, true)
    {
        return Err(fail("approved_root_unreadable", label));
    }
    Ok(canonical)
}

/// The workspace (or the working directory) and every explicit root, deduped.
pub(crate) fn approved_roots(
    workspace: Option<&str>,
    explicit: &[String],
    cwd: &Path,
    home: Option<&str>,
) -> Result<Vec<ApprovedRoot>, Contain> {
    let primary = readable_directory(workspace.unwrap_or(""), cwd, home, SELECTED)?;
    let mut roots = vec![ApprovedRoot {
        path: primary,
        label: SELECTED.to_owned(),
    }];
    for (index, value) in explicit.iter().enumerate() {
        let label = format!("explicit-root-{}", index + 1);
        let canonical = readable_directory(value, cwd, home, &label)?;
        if !roots.iter().any(|root| root.path == canonical) {
            roots.push(ApprovedRoot {
                path: canonical,
                label,
            });
        }
    }
    Ok(roots)
}

/// `skill` for `SKILL.md` and `mcp` for `.mcp.json`, when that source is requested.
pub(crate) fn target_kind(target: &str, sources: &[String]) -> Option<&'static str> {
    let name = Path::new(target).file_name()?.to_str()?;
    let wants = |source: &str| sources.iter().any(|item| item == source);
    if wants("skill") && name == "SKILL.md" {
        return Some("skill");
    }
    if wants("mcp") && name == ".mcp.json" {
        return Some("mcp");
    }
    None
}

fn parent_or_self(path: &Path) -> &Path {
    path.parent().unwrap_or(path)
}

fn named(path: &Path, name: &str) -> bool {
    path.file_name().is_some_and(|value| value == name)
}

fn skill_root_for_file(path: &Path) -> PathBuf {
    let parent = parent_or_self(path);
    let grandparent = parent_or_self(parent);
    if named(grandparent, "skills") {
        return grandparent.to_path_buf();
    }
    parent.to_path_buf()
}

fn derived_scan_root(target: &Path, kind: &str, root: &ApprovedRoot) -> Result<PathBuf, Contain> {
    let candidate = if kind == "skill" {
        skill_root_for_file(target)
    } else {
        parent_or_self(target).to_path_buf()
    };
    canonical_scan_root(&candidate, root)
}

fn canonical_scan_root(candidate: &Path, root: &ApprovedRoot) -> Result<PathBuf, Contain> {
    let inside = resolve(candidate).filter(|(canonical, _)| canonical.starts_with(&root.path));
    let Some((canonical, meta)) = inside else {
        return Err(fail("derived_scan_root_outside_approved_root", &root.label));
    };
    let mode = mode_of(&meta);
    if !meta.is_dir()
        || mode & READ_BITS == 0
        || mode & EXEC_BITS == 0
        || !accessible(&canonical, true)
    {
        return Err(fail("derived_scan_root_unreadable", &root.label));
    }
    Ok(canonical)
}

fn most_specific<'a>(target: &Path, roots: &'a [ApprovedRoot]) -> Option<&'a ApprovedRoot> {
    let mut ordered: Vec<&ApprovedRoot> = roots.iter().collect();
    ordered.sort_by_key(|root| std::cmp::Reverse(root.path.components().count()));
    ordered
        .into_iter()
        .find(|root| target.starts_with(&root.path))
}

fn readable_file(meta: &std::fs::Metadata, path: &Path) -> bool {
    meta.is_file() && mode_of(meta) & READ_BITS != 0 && accessible(path, false)
}

pub(crate) fn validated_target(
    target: &str,
    kind: &'static str,
    resolution_root: &Path,
    home: Option<&str>,
    roots: &[ApprovedRoot],
) -> Result<Validated, Contain> {
    let expanded = expand(target, home);
    let candidate = if expanded.is_absolute() {
        expanded
    } else {
        resolution_root.join(expanded)
    };
    let (path, meta) = resolve(&candidate).ok_or_else(|| fail("target_unresolved", SELECTED))?;
    let Some(root) = most_specific(&path, roots) else {
        return Err(fail("target_outside_approved_roots", "all-approved-roots"));
    };
    if !meta.is_file() || mode_of(&meta) & READ_BITS == 0 {
        return Err(fail("target_not_readable_regular_file", &root.label));
    }
    if !accessible(&path, false) {
        return Err(fail("target_unreadable", &root.label));
    }
    let scan_root = derived_scan_root(&path, kind, root)?;
    Ok(Validated {
        path: Some(path),
        scan_root,
        approved_root: root.clone(),
        kind,
    })
}

pub(crate) fn validated_redacted(
    kind: &'static str,
    primary: &ApprovedRoot,
) -> Result<Validated, Contain> {
    let skills = primary.path.join("skills");
    let scan_root = if kind == "skill" && skills.is_dir() {
        skills
    } else {
        primary.path.clone()
    };
    let scan_root = canonical_scan_root(&scan_root, primary)?;
    Ok(Validated {
        path: None,
        scan_root,
        approved_root: primary.clone(),
        kind,
    })
}

pub(crate) fn revalidate(target: &Validated) -> Result<(), Contain> {
    let label = target.approved_root.label.as_str();
    let root = target.approved_root.path.to_string_lossy().into_owned();
    let current = readable_directory(&root, Path::new("/"), None, label)?;
    if current != target.approved_root.path {
        return Err(fail("approved_root_changed", label));
    }
    if let Some(path) = &target.path {
        let changed = || fail("target_changed", label);
        let (resolved, meta) = resolve(path).ok_or_else(changed)?;
        if &resolved != path || !readable_file(&meta, &resolved) {
            return Err(changed());
        }
        if derived_scan_root(&resolved, target.kind, &target.approved_root)? != target.scan_root {
            return Err(fail("derived_scan_root_changed", label));
        }
    }
    if canonical_scan_root(&target.scan_root, &target.approved_root)? != target.scan_root {
        return Err(fail("derived_scan_root_changed", label));
    }
    Ok(())
}
