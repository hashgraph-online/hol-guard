//! Hooks paths that leave an inspection read with no hook to run.

/// Hooks never run for an inspection read, and a path with no hook files adds
/// none. `/dev/null` is the conventional way to disable hooks entirely.
const GIT_HOOK_NAMES: &[&str] = &[
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "pre-commit",
    "pre-merge-commit",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "pre-push",
    "pre-receive",
    "update",
    "proc-receive",
    "post-receive",
    "post-update",
    "reference-transaction",
    "push-to-checkout",
    "pre-auto-gc",
    "post-rewrite",
    "sendemail-validate",
    "fsmonitor-watchman",
    "p4-changelist",
    "p4-prepare-changelist",
    "p4-post-changelist",
    "p4-pre-submit",
    "post-index-change",
];

/// `/dev/null`, which switches hooks off. Git for Windows does not map it to
/// the null device but resolves it below the root of whatever directory a
/// hook runs in, which this check without a working directory cannot see, so
/// there it never counts as switched off.
pub(super) fn null_hooks_path(value: &str) -> bool {
    value == "/dev/null" && !cfg!(windows)
}

pub(super) fn hooks_path_names_no_hooks(
    value: &str,
    cwd: Option<&str>,
    arguments: &[String],
) -> bool {
    // Windows resolves a rooted path without a drive, and the `/<hook>` an
    // empty hooks path makes, against the root of the directory a hook runs
    // in. Of those only the conventional `/dev/null` and the empty path are
    // proven, and only while that root and every drive are local and hold no
    // hooks.
    let path = std::path::Path::new(value);
    if cfg!(windows) && (value.is_empty() || path.has_root() && !path.is_absolute()) {
        let below = match value {
            "/dev/null" => "dev\\null",
            "" => "",
            _ => return false,
        };
        return windows_rooted_names_no_hooks(below, cwd, arguments);
    }
    if value == "/dev/null" {
        return true;
    }
    // Git joins an empty hooks path as `/<hook>`, so it names the filesystem root.
    if value.is_empty() {
        return GIT_HOOK_NAMES.iter().all(|name| {
            std::fs::symlink_metadata(std::path::Path::new("/").join(name))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        });
    }
    if !path.is_absolute() || value.starts_with('~') {
        return false;
    }
    match std::fs::symlink_metadata(path) {
        Err(error) => {
            error.kind() == std::io::ErrorKind::NotFound
                // No such drive, or no media in the drive.
                || cfg!(windows) && matches!(error.raw_os_error(), Some(15 | 21))
        }
        Ok(metadata) => {
            metadata.is_dir()
                && std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
        }
    }
}

/// A hooks path `below` every root on Windows for a command run from `cwd`
/// with `arguments`: the working directory, every `-C` step and any
/// `--git-dir` or `--work-tree` must stay on a local drive, and no drive may
/// hold a hook there.
fn windows_rooted_names_no_hooks(below: &str, cwd: Option<&str>, arguments: &[String]) -> bool {
    let Some(cwd) = cwd.map(std::path::PathBuf::from) else {
        return false;
    };
    let mut directory = cwd.clone();
    let mut roots = vec![cwd];
    let mut index = 0;
    while let Some(argument) = arguments.get(index) {
        index += 1;
        let target = match argument.as_str() {
            "-c" => {
                index += 1;
                continue;
            }
            "-C" | "--git-dir" | "--work-tree" => {
                index += 1;
                arguments.get(index - 1).map(String::as_str)
            }
            // The subcommand ends the global options.
            _ if !argument.starts_with('-') => break,
            _ => argument
                .strip_prefix("--git-dir=")
                .or_else(|| argument.strip_prefix("--work-tree=")),
        };
        let Some(target) = target else {
            continue;
        };
        // Git Bash rewrites a rooted path without a drive to a directory of
        // its own, so where it lands is unknown here.
        let rooted = std::path::Path::new(target);
        if rooted.has_root() && !rooted.is_absolute() {
            return false;
        }
        let joined = directory.join(target);
        if argument == "-C" {
            directory = joined.clone();
        }
        roots.push(joined);
    }
    let roots = roots.iter().map(|root| root.as_path()).collect::<Vec<_>>();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    rooted_hooks_inert(below, GIT_HOOK_NAMES, &roots, deadline)
}

/// Whether Git for Windows finds none of `hooks` in the directory `below`
/// the root of the working directory (`\dev\null` for `core.hooksPath=
/// /dev/null`) for a process whose working directory is one of `roots`.
///
/// Git resolves that driveless path against the root of the working
/// directory, and the `nul` Git Bash passes for `/dev/null` against the
/// working directory itself, so both must be free of hooks. A root on a share
/// or other non-drive volume is not probed, nor is a remote drive, which can stall the probe; either stays unproven. Every
/// local drive is checked, since Git may move to the worktree on another drive
/// before a hook runs, and the probe stops unproven once `deadline` passes.
#[cfg(windows)]
pub(crate) fn rooted_hooks_inert(
    below: &str,
    hooks: &[&str],
    roots: &[&std::path::Path],
    deadline: std::time::Instant,
) -> bool {
    use std::path::{Component, Prefix};
    let drive = |path: &std::path::Path| match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => {
                Some(char::from(letter.to_ascii_uppercase()))
            }
            _ => None,
        },
        _ => None,
    };
    let Some(letters) = guard_runtime_windows_process::local_drive_letters() else {
        return false;
    };
    let on_local_drive =
        |path: &std::path::Path| drive(path).is_some_and(|letter| letters.contains(&letter));
    for &root in roots {
        if std::time::Instant::now() >= deadline || !on_local_drive(root) {
            return false;
        }
        // A link can move a drive path onto a share, so its target counts.
        match std::fs::canonicalize(root) {
            Ok(canonical) if on_local_drive(&canonical) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return false,
        }
        // Git Bash rewrites the argument `core.hooksPath=/dev/null` to
        // `core.hooksPath=nul`, which Git resolves below the directory a hook
        // runs in rather than below its root.
        let msys = below == "dev\\null"
            && !hooks.iter().all(|hook| {
                std::fs::symlink_metadata(root.join("nul").join(hook))
                    .is_err_and(|error| absent(&error))
            });
        if msys {
            return false;
        }
    }
    letters.iter().all(|letter| {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        let directory = std::path::PathBuf::from(format!("{letter}:\\{below}"));
        match std::fs::symlink_metadata(&directory) {
            Err(error) => absent(&error),
            Ok(metadata) if !metadata.is_dir() => true,
            Ok(_) => hooks.iter().all(|hook| {
                std::fs::symlink_metadata(directory.join(hook)).is_err_and(|error| absent(&error))
            }),
        }
    })
}

/// Only Windows resolves a driveless hooks path below a drive.
#[cfg(not(windows))]
pub(crate) fn rooted_hooks_inert(
    _below: &str,
    _hooks: &[&str],
    _roots: &[&std::path::Path],
    _deadline: std::time::Instant,
) -> bool {
    false
}

/// Nothing there: not found, or the drive emptied or removed meanwhile.
#[cfg(windows)]
fn absent(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound || matches!(error.raw_os_error(), Some(15 | 21))
}

#[cfg(all(test, windows))]
mod tests {
    use super::hooks_path_names_no_hooks;

    #[test]
    fn windows_proves_only_dev_null_from_a_local_drive() {
        let temp = std::env::temp_dir();
        let cwd = temp.to_str().unwrap();
        let names = |value: &str, cwd: Option<&str>, arguments: &[&str]| {
            let arguments = arguments.iter().map(|a| a.to_string()).collect::<Vec<_>>();
            hooks_path_names_no_hooks(value, cwd, &arguments)
        };
        assert!(names("/dev/null", Some(cwd), &["status"]));
        assert!(names("/dev/null", Some(cwd), &["-C", "sub", "status"]));
        // No working directory, another driveless spelling, or a root on a
        // share stays unproven.
        assert!(!names("/dev/null", None, &["status"]));
        assert!(!names("/tmp/no-hooks", Some(cwd), &["status"]));
        assert!(!names("\\dev\\null", Some(cwd), &["status"]));
        assert!(!names(
            "/dev/null",
            Some(r"\\server\share\repo"),
            &["status"]
        ));
        for arguments in [
            &["-C", r"\\server\share\repo", "status"][..],
            &["-C", "//server/share/repo", "status"],
            &["--git-dir=//server/share/repo/.git", "status"],
            &["--work-tree", r"\\?\UNC\server\share\repo", "status"],
            // Git Bash would move this to a directory of its own.
            &["-C", "/tmp/repo", "status"],
        ] {
            assert!(!names("/dev/null", Some(cwd), arguments), "{arguments:?}");
        }
    }

    /// Git Bash passes `core.hooksPath=/dev/null` to Git as `nul`, which Git
    /// resolves below the working directory, so a hook there is refused.
    #[test]
    fn windows_refuses_a_hook_git_bash_finds_below_nul() {
        let root = std::env::temp_dir().join(format!("guard-nul-hooks-{}", std::process::id()));
        // Only the extended-length form can create a directory named `nul`.
        let verbatim = std::path::PathBuf::from(format!(r"\\?\{}", root.display()));
        std::fs::create_dir_all(verbatim.join("nul")).unwrap();
        let cwd = root.to_str().unwrap().to_owned();
        let empty = hooks_path_names_no_hooks("/dev/null", Some(&cwd), &[]);
        std::fs::write(
            verbatim.join("nul").join("post-index-change"),
            "#!/bin/sh\n",
        )
        .unwrap();
        let planted = hooks_path_names_no_hooks("/dev/null", Some(&cwd), &[]);
        std::fs::remove_dir_all(&verbatim).unwrap();
        assert!(empty);
        assert!(!planted);
    }
}
