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

pub(super) fn hooks_path_names_no_hooks(value: &str) -> bool {
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
    let path = std::path::Path::new(value);
    if !path.is_absolute() || value.starts_with('~') {
        return false;
    }
    match std::fs::symlink_metadata(path) {
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        Ok(metadata) => {
            metadata.is_dir()
                && std::fs::read_dir(path).is_ok_and(|mut entries| entries.next().is_none())
        }
    }
}
