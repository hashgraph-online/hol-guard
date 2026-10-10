//! Bounded Git pathspec resolution and the selection identity for the Codex
//! read-only `git diff` review.
//!
//! The host runs the two bounded git queries; everything else (pathspec
//! support rules, containment, per-entry filesystem identity, the canonical
//! JSON that is hashed) lives here.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::codex_output_env::{Ctx, GitCheck, GitRun};
use crate::codex_output_fs as pyfs;
use crate::codex_output_identity::{selection_identity, IdentityPayload, WorktreeEntry};
use crate::codex_output_py::{py_strip, PyPath};
use crate::codex_output_source_paths::py_path;

const PATH_LIMIT: usize = 10_000;
const SUPPORTED_LONG_MAGIC: &[&str] = &["exclude", "glob", "icase", "literal", "top"];
pub(crate) const GLOBAL_MODES: &[&str] = &[
    "--glob-pathspecs",
    "--literal-pathspecs",
    "--no-literal-pathspecs",
    "--noglob-pathspecs",
];

/// One exact tracked-file selection or a stable incomplete reason.
pub(crate) struct Resolution {
    pub(crate) complete: bool,
    pub(crate) repository_root: Option<PyPath>,
    pub(crate) resolved_paths: Vec<PyPath>,
    pub(crate) selection_identity: Option<String>,
}

/// `git_pathspec_is_supported`.
pub(crate) fn pathspec_is_supported(pathspec: &str) -> bool {
    if pathspec.is_empty() || pathspec.contains('\0') {
        return false;
    }
    if !pathspec.starts_with(':') {
        return true;
    }
    if let Some(after_open) = pathspec.strip_prefix(":(") {
        let Some(closing) = after_open.find(')') else {
            return false;
        };
        let magic_text = &after_open[..closing];
        if magic_text.is_empty() {
            return false;
        }
        let magic: HashSet<String> = magic_text
            .split(',')
            .map(|item| py_strip(item).to_lowercase())
            .filter(|item| !item.is_empty())
            .collect();
        if magic.is_empty()
            || !magic
                .iter()
                .all(|item| SUPPORTED_LONG_MAGIC.contains(&item.as_str()))
        {
            return false;
        }
        return !(magic.contains("glob") && magic.contains("literal"));
    }
    if pathspec.starts_with(":!") || pathspec.starts_with(":^") || pathspec.starts_with(":/") {
        return pathspec.chars().count() > 2;
    }
    pathspec == ":"
}

/// `git_literal_pathspec_path`.
pub(crate) fn literal_pathspec_path(pathspec: &str) -> Option<&str> {
    if let Some(literal) = pathspec.strip_prefix(":(literal)") {
        return (!literal.is_empty()).then_some(literal);
    }
    if pathspec.starts_with(':') || pathspec.chars().any(|c| matches!(c, '*' | '?' | '[')) {
        return None;
    }
    Some(pathspec)
}

fn canonical(path: &PyPath) -> Option<PyPath> {
    let real: PathBuf = std::fs::canonicalize(path.to_string()).ok()?;
    Some(py_path(&real))
}

/// `git_literal_file_selection`.
pub(crate) fn literal_file_selection(
    pathspecs: &[String],
    cwd: Option<&PyPath>,
) -> Option<Vec<PyPath>> {
    let cwd = cwd?;
    if pathspecs.is_empty() {
        return None;
    }
    let effective = canonical(cwd)?;
    let mut selected = Vec::new();
    for pathspec in pathspecs {
        let literal = literal_pathspec_path(pathspec)?;
        let candidate = effective.join(literal);
        if pyfs::is_symlink(&candidate).ok()? || !pyfs::is_file(&candidate).ok()? {
            return None;
        }
        selected.push(canonical(&candidate)?);
    }
    Some(selected)
}

fn cwd_identity_text(cwd: Option<&PyPath>, ctx: &Ctx) -> Option<Option<PyPath>> {
    let Some(cwd) = cwd else {
        return Some(None);
    };
    let absolute = if cwd.is_absolute() {
        cwd.clone()
    } else {
        ctx.process_cwd.join(&cwd.to_string())
    };
    pyfs::resolve(&absolute).map(Some)
}

fn incomplete(
    ctx: &Ctx,
    reason: &str,
    cwd: Option<&PyPath>,
    pathspecs: &[String],
    global_modes: &[String],
) -> Option<Resolution> {
    let resolved_cwd = cwd_identity_text(cwd, ctx)?;
    let identity = selection_identity(&IdentityPayload {
        reason_code: reason,
        cwd: resolved_cwd.as_ref(),
        repository_root: None,
        pathspecs,
        global_modes,
        resolved_paths: &[],
        index_entries: &[],
        worktree_entries: &[],
    });
    Some(Resolution {
        complete: false,
        repository_root: None,
        resolved_paths: Vec::new(),
        selection_identity: Some(identity),
    })
}

fn is_ascii_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn executable(path: &PyPath) -> bool {
    #[cfg(unix)]
    {
        nix::unistd::access(path.to_string().as_str(), nix::unistd::AccessFlags::X_OK).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

fn metadata_fields(meta: &std::fs::Metadata) -> (u64, u64, u32, u64, i128) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            meta.dev(),
            meta.ino(),
            meta.mode(),
            meta.size(),
            i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        )
    }
    #[cfg(not(unix))]
    {
        let modified = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |elapsed| elapsed.as_nanos() as i128);
        (0, 0, 0, meta.len(), modified)
    }
}

fn is_regular(meta: &std::fs::Metadata) -> bool {
    meta.is_file()
}

#[allow(clippy::too_many_lines)]
fn resolve_inner(
    ctx: &Ctx,
    pathspecs: &[String],
    cwd: Option<&PyPath>,
    global_modes: &[String],
) -> Option<Resolution> {
    let fail = |reason: &str| incomplete(ctx, reason, cwd, pathspecs, global_modes);
    let Some(cwd_value) = cwd else {
        return fail("git_pathspec_cwd_unavailable");
    };
    if pathspecs.iter().any(|spec| !pathspec_is_supported(spec)) {
        return fail("git_pathspec_unsupported_magic");
    }
    if global_modes
        .iter()
        .any(|mode| !GLOBAL_MODES.contains(&mode.as_str()))
    {
        return fail("git_pathspec_unsupported_global_mode");
    }
    let Some(git_executable) = ctx.host.git_executable() else {
        return fail("git_pathspec_git_unavailable");
    };
    let (Some(git_path), Some(effective_cwd)) = (
        canonical(&PyPath::new(&git_executable)),
        canonical(cwd_value),
    ) else {
        return fail("git_pathspec_cwd_unavailable");
    };
    if !pyfs::is_file(&git_path).unwrap_or(false)
        || !executable(&git_path)
        || !pyfs::is_dir(&effective_cwd).unwrap_or(false)
    {
        return fail("git_pathspec_git_unavailable");
    }
    let git_text = git_path.to_string();
    let cwd_text = effective_cwd.to_string();
    // The resident only runs a `git` it has vetted for this directory, and only
    // with a routing environment that cannot redirect the repository queries.
    if !ctx
        .host
        .git_safety(GitCheck::ResolveBinary, Some(&cwd_text), &[])
        || !ctx
            .host
            .git_safety(GitCheck::ConfigEnvironmentClean, None, &[])
    {
        return fail("git_pathspec_git_unavailable");
    }
    let mut root_args: Vec<String> = global_modes.to_vec();
    root_args.extend(["-C", &cwd_text, "rev-parse", "--show-toplevel"].map(str::to_owned));
    let root_output = match ctx.host.run_git(&git_text, &root_args, &cwd_text) {
        GitRun::Output(bytes) => bytes,
        GitRun::Failed(reason) => return fail(reason),
    };
    let root_text = String::from_utf8_lossy(&root_output).into_owned();
    let Some(repository_root) = canonical(&PyPath::new(py_strip(&root_text))) else {
        return fail("git_pathspec_repository_unavailable");
    };
    if !pyfs::is_dir(&repository_root).unwrap_or(false)
        || effective_cwd.relative_to(&repository_root).is_none()
    {
        return fail("git_pathspec_outside_repository");
    }
    let mut list_args: Vec<String> = global_modes.to_vec();
    list_args.extend(
        [
            "-C",
            &cwd_text,
            "ls-files",
            "-z",
            "--cached",
            "--stage",
            "--full-name",
            "--",
        ]
        .map(str::to_owned),
    );
    list_args.extend(pathspecs.iter().cloned());
    let root_dir = repository_root.to_string();
    let output = match ctx.host.run_git(&git_text, &list_args, &root_dir) {
        GitRun::Output(bytes) => bytes,
        GitRun::Failed(reason) => return fail(reason),
    };
    let body: &[u8] = output.strip_suffix(&[0]).unwrap_or(&output);
    let mut raw_paths: Vec<&[u8]> = body.split(|byte| *byte == 0).collect();
    if raw_paths == [&b""[..]] {
        raw_paths.clear();
    }
    if raw_paths.len() > PATH_LIMIT {
        return fail("git_pathspec_path_limit_exceeded");
    }
    let mut resolved_paths: Vec<PyPath> = Vec::new();
    let mut index_entries: Vec<(Vec<u8>, String, String)> = Vec::new();
    let mut worktree_entries: Vec<WorktreeEntry> = Vec::new();
    let mut seen: HashSet<&[u8]> = HashSet::new();
    for raw_entry in raw_paths {
        let Some(tab) = raw_entry.iter().position(|byte| *byte == b'\t') else {
            return fail("git_pathspec_malformed_output");
        };
        let (metadata, raw_path) = (&raw_entry[..tab], &raw_entry[tab + 1..]);
        let fields: Vec<&[u8]> = metadata
            .split(|byte| is_ascii_space(*byte))
            .filter(|field| !field.is_empty())
            .collect();
        if fields.len() != 3 || raw_path.is_empty() || !fields.iter().all(|field| field.is_ascii())
        {
            return fail("git_pathspec_malformed_output");
        }
        let mode = String::from_utf8_lossy(fields[0]).into_owned();
        let object_id = String::from_utf8_lossy(fields[1]).into_owned();
        let stage = String::from_utf8_lossy(fields[2]).into_owned();
        if mode == "120000" {
            return fail("git_pathspec_symlink_unresolved");
        }
        if !matches!(mode.as_str(), "100644" | "100755") || stage != "0" {
            return fail("git_pathspec_non_regular_path");
        }
        if !matches!(object_id.len(), 40 | 64)
            || !object_id
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return fail("git_pathspec_malformed_output");
        }
        let parts: Vec<&[u8]> = raw_path
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty() && *part != b".")
            .collect();
        if raw_path[0] == b'/' || parts.contains(&&b".."[..]) || !seen.insert(raw_path) {
            return fail("git_pathspec_outside_repository");
        }
        let Ok(relative_names) = parts
            .iter()
            .map(|part| std::str::from_utf8(part))
            .collect::<Result<Vec<&str>, _>>()
        else {
            return fail("git_pathspec_path_unresolved");
        };
        let candidate = relative_names
            .iter()
            .fold(repository_root.clone(), |base, name| base.join(name));
        let Ok(is_link) = pyfs::is_symlink(&candidate) else {
            return fail("git_pathspec_path_unresolved");
        };
        if is_link {
            return fail("git_pathspec_symlink_unresolved");
        }
        let (Ok(exists), Ok(is_file)) = (pyfs::exists(&candidate), pyfs::is_file(&candidate))
        else {
            return fail("git_pathspec_path_unresolved");
        };
        if exists && !is_file {
            return fail("git_pathspec_non_regular_path");
        }
        let Some(resolved) = pyfs::resolve(&candidate) else {
            return fail("git_pathspec_path_unresolved");
        };
        if exists {
            let Ok(meta) = std::fs::metadata(candidate.to_string()) else {
                return fail("git_pathspec_path_unresolved");
            };
            if !is_regular(&meta) {
                return fail("git_pathspec_non_regular_path");
            }
            let (device, inode, file_mode, size, mtime_ns) = metadata_fields(&meta);
            worktree_entries.push(WorktreeEntry::Present {
                relative: raw_path.to_vec(),
                device,
                inode,
                mode: file_mode,
                size,
                mtime_ns,
            });
        } else {
            worktree_entries.push(WorktreeEntry::Missing {
                relative: raw_path.to_vec(),
            });
        }
        if resolved.relative_to(&repository_root).is_none() {
            return fail("git_pathspec_outside_repository");
        }
        resolved_paths.push(resolved);
        index_entries.push((raw_path.to_vec(), mode, object_id));
    }
    let reason = if resolved_paths.is_empty() {
        "git_pathspec_no_match"
    } else {
        "git_pathspec_resolved"
    };
    let relative_resolved: Vec<String> = resolved_paths
        .iter()
        .filter_map(|path| path.relative_to(&repository_root))
        .map(|parts| parts.join("/"))
        .collect();
    let identity = selection_identity(&IdentityPayload {
        reason_code: reason,
        cwd: Some(&effective_cwd),
        repository_root: Some(&repository_root),
        pathspecs,
        global_modes,
        resolved_paths: &relative_resolved,
        index_entries: &index_entries,
        worktree_entries: &worktree_entries,
    });
    Some(Resolution {
        complete: true,
        repository_root: Some(repository_root),
        resolved_paths,
        selection_identity: Some(identity),
    })
}

/// `resolve_git_pathspecs`. A resolution that cannot even be described (a
/// symlink loop in the working directory, where Python raised) is incomplete
/// without an identity.
pub(crate) fn resolve_git_pathspecs(
    ctx: &Ctx,
    pathspecs: &[String],
    cwd: Option<&PyPath>,
    global_modes: &[String],
) -> Resolution {
    resolve_inner(ctx, pathspecs, cwd, global_modes).unwrap_or(Resolution {
        complete: false,
        repository_root: None,
        resolved_paths: Vec::new(),
        selection_identity: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_rules_follow_python() {
        assert!(pathspec_is_supported("src/a.py"));
        assert!(!pathspec_is_supported(""));
        assert!(pathspec_is_supported(":(top,literal)a"));
        assert!(!pathspec_is_supported(":(glob,literal)a"));
        assert!(!pathspec_is_supported(":(attr:x)a"));
        assert!(pathspec_is_supported(":!a"));
        assert!(!pathspec_is_supported(":!"));
        assert!(pathspec_is_supported(":"));
        assert!(!pathspec_is_supported(":x"));
        assert_eq!(literal_pathspec_path(":(literal)a*"), Some("a*"));
        assert_eq!(literal_pathspec_path("a*"), None);
    }

    #[test]
    fn supported_magic_is_explicit_and_ambiguous_magic_is_incomplete() {
        for supported in [
            "src/app.py",
            ":(top)src/app.py",
            ":(literal)notes with spaces.md",
            ":(glob)src/**/*.py",
            ":(top,glob,icase)SRC/**/*.PY",
            ":(exclude,glob)**/*.env",
            ":!*.env",
            ":^*.env",
            ":/src/app.py",
        ] {
            assert!(pathspec_is_supported(supported), "{supported}");
        }
        for unsupported in [
            "",
            "bad\0path",
            ":(attr:guard)src/app.py",
            ":(glob,literal)src/*.py",
            ":(unknown)src/app.py",
            ":(globsrc/*.py",
        ] {
            assert!(!pathspec_is_supported(unsupported), "{unsupported:?}");
        }
    }
}
