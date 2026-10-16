//! Repository-level checks for a Git read the configuration probe cleared.
//!
//! Configuration alone does not cover two ways a read can start code. Status
//! and diff refresh a stat-dirty index and then run the repository's
//! `post-index-change` hook, wherever `core.hooksPath` puts it. And below the
//! shared temporary directory another local user could rewrite the
//! configuration or a hook between this probe and the read unless the
//! repository belongs to the current user and no one else can write it.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const PATH_LIMIT: u64 = 3 * 4096;

/// Whether the repository `base` points at cannot start a hook for this read
/// and, below the shared temporary directory, is owned by the current user
/// and writable by no one else.
pub(in crate::pretool) fn repository_inert(
    base: &Command,
    operation: &str,
    arguments: &[String],
    deadline: Instant,
) -> Option<bool> {
    let refreshes = matches!(operation, "status" | "diff");
    if refreshes && !super::submodules_are_inert(base, arguments, deadline)? {
        return Some(false);
    }
    let roots = super::super::git_routes::owned_temporary_roots();
    // Without a hook to find and with no route into a shared temporary
    // directory there is nothing left to inspect, so no process is started.
    if !refreshes && base.get_args().next().is_none() && !temporary(base, &roots) {
        return Some(true);
    }
    let paths = match lookup(base, refreshes, true, deadline)? {
        Some(paths) => paths,
        // A hook path below a file (`core.hooksPath=/dev/null`) cannot be
        // normalized, so ask for it as Git spells it; Git's own hook lookup
        // finds nothing there. A relative spelling stays unproven.
        None if refreshes => match lookup(base, refreshes, false, deadline)? {
            Some(paths) => paths,
            None => return super::outside_repository(base, deadline)?.then_some(true),
        },
        // Outside any repository there is no hook and no local configuration.
        None => return super::outside_repository(base, deadline)?.then_some(true),
    };
    let (directories, hook) = paths.split_at(2);
    if !directories.iter().all(|directory| directory.is_absolute()) {
        return None;
    }
    let mut guarded: Vec<PathBuf> = directories.to_vec();
    guarded.push(directories[1].join("config"));
    if let Some(parent) = hook.first().and_then(|hook| hook.parent()) {
        guarded.push(parent.to_path_buf());
    }
    if !guarded.iter().all(|path| owned_where_shared(path, &roots)) {
        return Some(false);
    }
    if let Some(hook) = hook.first().filter(|hook| drive_relative_root(hook)) {
        return null_hook_inert(base, directories, hook, deadline);
    }
    Some(hook.iter().all(|hook| hook_inert(hook)))
}

/// Git for Windows answers the hook below `core.hooksPath=/dev/null` without
/// a drive and resolves it against the root of the directory the hook runs
/// in: the working directory, a `-C` target, the worktree or, for a bare
/// repository, the Git directory. Only that spelling is proven, and only
/// while every one of those roots and every drive is local and holds no
/// hook. Any other rooted path without a drive stays unproven.
fn null_hook_inert(
    base: &Command,
    directories: &[PathBuf],
    hook: &Path,
    deadline: Instant,
) -> Option<bool> {
    let null = Path::new("/dev/null");
    if hook.parent() != Some(null) || hook.file_name()? != "post-index-change" {
        return None;
    }
    let mut directory = match base.get_current_dir() {
        Some(directory) => directory.to_path_buf(),
        None => std::env::current_dir().ok()?,
    };
    let mut roots = vec![directory.clone()];
    let mut arguments = base.get_args();
    while let Some(argument) = arguments.next() {
        if argument == "-C" {
            // Git Bash rewrites a rooted target without a drive to a
            // directory of its own, so this probe cannot follow it.
            let target = Path::new(arguments.next()?);
            if drive_relative_root(target) {
                return None;
            }
            directory = directory.join(target);
            roots.push(directory.clone());
        }
    }
    roots.extend_from_slice(directories);
    roots.extend(toplevel(base, deadline)?);
    let roots = roots.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    let hooks = ["post-index-change"];
    Some(crate::command_compatibility::git_rooted_hooks_inert(
        "dev\\null",
        &hooks,
        &roots,
        deadline,
    ))
}

/// The worktree a hook would run in: `Some(None)` outside any worktree.
fn toplevel(base: &Command, deadline: Instant) -> Option<Option<PathBuf>> {
    let mut command = super::copy_command(base)?;
    command.args(["--no-pager", "rev-parse", "--show-toplevel"]);
    let (status, bytes) = super::output(&mut command, deadline, PATH_LIMIT)?;
    if !status.success() {
        return Some(None);
    }
    let mut paths = absolute_lines(&bytes, 1)?;
    paths.pop().filter(|path| path.is_absolute()).map(Some)
}

/// The absolute Git and common directories, then the `post-index-change` hook
/// path for a refreshing read: `Some(None)` when Git cannot answer, `None`
/// when the probe itself fails or an answer is not an absolute path.
fn lookup(
    base: &Command,
    refreshes: bool,
    normalized: bool,
    deadline: Instant,
) -> Option<Option<Vec<PathBuf>>> {
    let mut command = super::copy_command(base)?;
    command.args(["--no-pager", "rev-parse"]);
    if refreshes && !normalized {
        command.args(["--git-path", "hooks/post-index-change"]);
    }
    command.args(["--path-format=absolute", "--git-dir", "--git-common-dir"]);
    if refreshes && normalized {
        command.args(["--git-path", "hooks/post-index-change"]);
    }
    let (status, bytes) = super::output(&mut command, deadline, PATH_LIMIT)?;
    if !status.success() {
        return Some(None);
    }
    let mut paths = absolute_lines(&bytes, if refreshes { 3 } else { 2 })?;
    if refreshes && !normalized {
        paths.rotate_left(1);
    }
    Some(Some(paths))
}

fn temporary(base: &Command, roots: &[PathBuf]) -> bool {
    base.get_current_dir()
        .and_then(|directory| std::fs::canonicalize(directory).ok())
        .is_none_or(|directory| roots.iter().any(|root| directory.starts_with(root)))
}

/// A rooted path without a drive (`\dev\null`), which only Windows has.
fn drive_relative_root(path: &Path) -> bool {
    cfg!(windows) && path.has_root() && !path.is_absolute()
}

/// One absolute path per line, exactly `count` of them. A drive-relative
/// root is kept for the hook path; the caller requires drives on the rest.
fn absolute_lines(bytes: &[u8], count: usize) -> Option<Vec<PathBuf>> {
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix('\n').unwrap_or(text);
    let paths = text
        .split('\n')
        .map(|line| {
            let line = line.strip_suffix('\r').unwrap_or(line);
            let path = Path::new(line);
            (!line.is_empty()
                && !line.contains(['\r', '\0'])
                && (path.is_absolute() || drive_relative_root(path)))
            .then(|| PathBuf::from(line))
        })
        .collect::<Option<Vec<_>>>()?;
    (paths.len() == count).then_some(paths)
}

/// A missing hook, a directory or a plain non-executable file never runs, nor
/// does a hook path below a file (`core.hooksPath=/dev/null`).
fn hook_inert(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(error) => {
            error.kind() == std::io::ErrorKind::NotFound
                || path
                    .parent()
                    .and_then(|parent| std::fs::metadata(parent).ok())
                    .is_some_and(|metadata| !metadata.is_dir())
        }
        Ok(metadata) => {
            !(metadata.file_type().is_symlink() || metadata.is_file() && executable(&metadata))
        }
    }
}

#[cfg(unix)]
fn executable(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn executable(metadata: &std::fs::Metadata) -> bool {
    metadata.is_file()
}

/// A path that lands below a shared temporary root must belong to the current
/// user and grant no group or other write access. A missing path is judged by
/// its nearest existing ancestor, since whoever controls that directory could
/// create the path (a hook directory, say) between this probe and the read:
/// below a directory another user owns or anyone may write it stays reviewed.
/// A missing path straight below the shared root itself (`core.hooksPath=
/// /tmp/no-hooks`) is accepted: only a hostile co-resident account racing the
/// window between this probe and the read could create it there, while a
/// hook planted ahead of the read already exists and `hook_inert` screens it.
/// Elsewhere the sibling and workspace route proofs already decide where Git
/// may run.
#[cfg(unix)]
fn owned_where_shared(path: &Path, roots: &[PathBuf]) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (existing, missing) = match std::fs::canonicalize(path) {
        Ok(canonical) => (canonical, PathBuf::new()),
        // A dangling symlink is not missing: its target could appear later.
        Err(_) if std::fs::symlink_metadata(path).is_ok() => return false,
        Err(_) => match nearest_existing(path) {
            Some(pair) => pair,
            None => return false,
        },
    };
    let landing = existing.join(&missing);
    if !roots.iter().any(|root| landing.starts_with(root)) {
        return true;
    }
    if !missing.as_os_str().is_empty() && roots.contains(&existing) {
        return true;
    }
    let me = nix::unistd::geteuid().as_raw();
    std::fs::metadata(&existing)
        .is_ok_and(|metadata| metadata.uid() == me && metadata.mode() & 0o022 == 0)
}

/// The canonical nearest ancestor of a missing `path` and the components that
/// would still have to be created below it; `None` when an ancestor exists
/// but does not resolve or the missing part climbs with `..`.
#[cfg(unix)]
fn nearest_existing(path: &Path) -> Option<(PathBuf, PathBuf)> {
    for ancestor in path.ancestors().skip(1) {
        if let Ok(canonical) = std::fs::canonicalize(ancestor) {
            let missing = path.strip_prefix(ancestor).ok()?.to_path_buf();
            let climbs = missing
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)));
            return (!climbs).then_some((canonical, missing));
        }
        if std::fs::symlink_metadata(ancestor).is_ok() {
            return None;
        }
    }
    None
}

#[cfg(not(unix))]
fn owned_where_shared(_path: &Path, _roots: &[PathBuf]) -> bool {
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::{absolute_lines, owned_where_shared};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// A fresh directory standing in for a shared temporary root.
    fn root(tag: &str, mode: u32) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "guard-probe-repository-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("repo/.git")).unwrap();
        for directory in [root.join("repo/.git"), root.join("repo")] {
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::canonicalize(root).unwrap()
    }

    fn shared(root: &Path, relative: &str) -> bool {
        owned_where_shared(&root.join(relative), &[root.to_path_buf()])
    }

    #[test]
    fn missing_paths_others_could_create_stay_reviewed() {
        let root = root("writable", 0o1777);
        let foreign = root.join("foreign");
        std::fs::create_dir(&foreign).unwrap();
        std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o777)).unwrap();
        // `core.hooksPath` naming a directory not created yet below a
        // directory anyone may write.
        assert!(!shared(&root, "foreign/hooks"));
        assert!(!shared(&root, "foreign/hooks/nested"));
        assert!(!shared(&root, "repo/.git/missing/../../../shared-hooks"));
        std::os::unix::fs::symlink(root.join("absent"), root.join("dangling")).unwrap();
        assert!(!shared(&root, "dangling"));
        assert!(!shared(&root, "dangling/hooks"));
        // The shared root itself is never owned and private.
        assert!(!shared(&root, ""));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn missing_paths_inside_an_owned_repository_stay_allowed() {
        let root = root("owned", 0o1777);
        assert!(shared(&root, "repo/.git"));
        assert!(shared(&root, "repo/.git/hooks"));
        assert!(shared(&root, "repo/.git/hooks/nested"));
        // `core.hooksPath=/tmp/no-hooks`: missing straight below the root.
        assert!(shared(&root, "no-hooks"));
        assert!(shared(&root, "no-hooks/nested"));
        let elsewhere = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert!(owned_where_shared(
            &root.join("shared-hooks"),
            &[elsewhere.join("absent-root")]
        ));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rev_parse_paths_need_one_absolute_line_each() {
        let expected = Some(vec![PathBuf::from("/r/.git"), PathBuf::from("/r/.git")]);
        assert_eq!(absolute_lines(b"/r/.git\n/r/.git\n", 2), expected);
        assert_eq!(absolute_lines(b"/r/.git\r\n/r/.git\r\n", 2), expected);
        assert_eq!(absolute_lines(b"/r/.git\n", 2), None);
        assert_eq!(absolute_lines(b"/r/.git\n.git\n", 2), None);
        assert_eq!(absolute_lines(b"/r/.git\n\n/r/.git\n", 2), None);
    }
}
