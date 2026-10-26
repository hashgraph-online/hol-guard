//! Descriptor-level validation of a GitHub pull-request body file
//! (`github_pr_body_file.py`: `github_pr_body_file_is_safe`, the ancestor
//! chain and private-directory checks).

// Consumed by the later classifier slices.
#![allow(dead_code)]

use std::fs;
use std::path::Path;

use crate::codex_output_env::Ctx;
use crate::codex_output_py::PyPath;
use crate::sfrs_gh_body_file::{
    authored_location_root, is_pr_body_markdown_name, path_looks_sensitive, resolve_operand,
};
use crate::sfrs_gh_pyshim::current_uid;
use crate::shell_secret_read_support::classify_request_secret_path;

const MAX_PR_BODY_BYTES: u64 = 128 * 1024;
const MAX_PR_BODY_AGE_SECONDS: f64 = 24.0 * 60.0 * 60.0;
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const WORLD_WRITE: u32 = 0o002;
const STICKY: u32 = 0o1000;

/// `github_pr_body_file_is_safe`: validate locally authored PR text without
/// retaining its contents.
pub(crate) fn github_pr_body_file_is_safe(
    operand: &str,
    cwd: Option<&Path>,
    home_dir: Option<&Path>,
    ctx: &Ctx,
) -> bool {
    let (Some(cwd), Some(home_dir)) = (cwd, home_dir) else {
        return false;
    };
    let cwd_path = PyPath::new(&cwd.to_string_lossy());
    let home_path = PyPath::new(&home_dir.to_string_lossy());
    let Some(candidate) = resolve_operand(operand, &cwd_path, &home_path) else {
        return false;
    };
    if classify_request_secret_path(&candidate.to_string(), Some(cwd), Some(home_dir)).is_some()
        || path_looks_sensitive(&candidate)
        || !is_pr_body_markdown_name(candidate.name())
    {
        return false;
    }
    let Some(authored_root) = authored_location_root(&candidate, &cwd_path, &home_path, ctx) else {
        return false;
    };
    if !ancestor_chain_is_controlled(&candidate, &authored_root, ctx) {
        return false;
    }
    let Some(payload) = read_controlled_body(&candidate, ctx) else {
        return false;
    };
    match String::from_utf8(payload) {
        Ok(content) => !ctx.host.secret_content_found(&content, false),
        Err(_) => false,
    }
}

/// `_ancestor_chain_is_controlled`.
pub(crate) fn ancestor_chain_is_controlled(candidate: &PyPath, root: &PyPath, ctx: &Ctx) -> bool {
    // Windows workspaces and per-user temporary directories are ACL-bound;
    // there is no portable stdlib UID or ACL-owner API to duplicate here.
    if cfg!(windows) {
        return true;
    }
    let Some(uid) = current_uid(ctx) else {
        return false;
    };
    ancestor_chain_for_uid(candidate, root, uid)
}

#[cfg(unix)]
fn ancestor_chain_for_uid(candidate: &PyPath, root: &PyPath, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;

    let mut current = candidate.parent();
    while &current != root {
        if !private_directory_owned_by_current_user(&current, uid, None) {
            return false;
        }
        let parent = current.parent();
        if parent == current || current.relative_to(root).is_none() {
            return false;
        }
        current = parent;
    }
    let Ok(metadata) = fs::metadata(root.to_string()) else {
        return false;
    };
    if private_directory_owned_by_current_user(root, uid, Some(&metadata)) {
        return true;
    }
    metadata.is_dir()
        && (metadata.uid() == 0 || metadata.uid() == uid)
        && metadata.mode() & STICKY != 0
        && metadata.mode() & WORLD_WRITE != 0
}

#[cfg(not(unix))]
fn ancestor_chain_for_uid(_: &PyPath, _: &PyPath, _: u32) -> bool {
    true
}

/// `_private_directory_owned_by_current_user`.
#[cfg(unix)]
pub(crate) fn private_directory_owned_by_current_user(
    path: &PyPath,
    uid: u32,
    metadata: Option<&fs::Metadata>,
) -> bool {
    use std::os::unix::fs::MetadataExt;

    let owned;
    let metadata = match metadata {
        Some(metadata) => metadata,
        None => {
            let Ok(found) = fs::metadata(path.to_string()) else {
                return false;
            };
            owned = found;
            &owned
        }
    };
    metadata.is_dir() && metadata.uid() == uid && metadata.mode() & GROUP_OR_OTHER_WRITE == 0
}

#[cfg(not(unix))]
pub(crate) fn private_directory_owned_by_current_user(
    _: &PyPath,
    _: u32,
    _: Option<&fs::Metadata>,
) -> bool {
    false
}

/// Open the body without following links and read it while re-checking that
/// the path, descriptor and bytes describe one unchanged regular file.
#[cfg(unix)]
fn read_controlled_body(candidate: &PyPath, ctx: &Ctx) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::sfrs_file_identity::full_stat_identity;

    let path = candidate.to_string();
    let path_metadata = fs::symlink_metadata(&path).ok()?;
    // A non-regular entry can never pass the checks below; refusing it here
    // keeps a FIFO from blocking the open.
    if !path_metadata.file_type().is_file() {
        return None;
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if (metadata.dev(), metadata.ino()) != (path_metadata.dev(), path_metadata.ino()) {
        return None;
    }
    if full_stat_identity(&metadata) != full_stat_identity(&path_metadata) {
        return None;
    }
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        return None;
    }
    if metadata.size() == 0 || metadata.size() > MAX_PR_BODY_BYTES {
        return None;
    }
    let uid = current_uid(ctx)?;
    if metadata.uid() != uid || metadata.mode() & GROUP_OR_OTHER_WRITE != 0 {
        return None;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_secs_f64();
    let modified = metadata.mtime() as f64 + metadata.mtime_nsec() as f64 / 1e9;
    let age_seconds = now - modified;
    if !(-60.0..=MAX_PR_BODY_AGE_SECONDS).contains(&age_seconds) {
        return None;
    }
    let mut payload = vec![0u8; usize::try_from(MAX_PR_BODY_BYTES).ok()? + 1];
    let read = file.read(&mut payload).ok()?;
    payload.truncate(read);
    if u64::try_from(payload.len()).ok()? != metadata.size() {
        return None;
    }
    if full_stat_identity(&file.metadata().ok()?) != full_stat_identity(&metadata) {
        return None;
    }
    let after = fs::symlink_metadata(&path).ok()?;
    if full_stat_identity(&after) != full_stat_identity(&path_metadata) {
        return None;
    }
    Some(payload)
}

/// Windows uses the existing single-link, identity-bound native file service.
/// Its handle denies write/delete sharing through every byte and identity check.
#[cfg(windows)]
fn read_controlled_body(candidate: &PyPath, _ctx: &Ctx) -> Option<Vec<u8>> {
    use guard_runtime_windows_process::{
        handle_file_id, is_single_link_handle, open_bound_regular_file, regular_file_id,
    };
    use std::io::Read;
    use std::time::SystemTime;

    let path = std::path::PathBuf::from(candidate.to_string());
    let path_metadata = fs::symlink_metadata(&path).ok()?;
    if !path_metadata.is_file() || path_metadata.file_type().is_symlink() {
        return None;
    }
    let (identity, links) = regular_file_id(&path, false).ok()?;
    if links != 1 {
        return None;
    }
    let mut file = open_bound_regular_file(&path).ok()?;
    let metadata = file.metadata().ok()?;
    if handle_file_id(&file).ok()? != identity
        || !is_single_link_handle(&file).ok()?
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_PR_BODY_BYTES
    {
        return None;
    }
    let stable = |left: &fs::Metadata, right: &fs::Metadata| {
        left.is_file() == right.is_file()
            && left.len() == right.len()
            && left.modified().ok() == right.modified().ok()
            && left.created().ok() == right.created().ok()
    };
    if !stable(&metadata, &path_metadata) {
        return None;
    }
    let modified = metadata.modified().ok()?;
    let age = match SystemTime::now().duration_since(modified) {
        Ok(age) => age.as_secs_f64(),
        Err(error) => -error.duration().as_secs_f64(),
    };
    if !(-60.0..=MAX_PR_BODY_AGE_SECONDS).contains(&age) {
        return None;
    }
    let mut payload = Vec::with_capacity(usize::try_from(metadata.len()).ok()?);
    Read::by_ref(&mut file)
        .take(MAX_PR_BODY_BYTES + 1)
        .read_to_end(&mut payload)
        .ok()?;
    let after_path = fs::symlink_metadata(&path).ok()?;
    if u64::try_from(payload.len()).ok()? != metadata.len()
        || !stable(&file.metadata().ok()?, &metadata)
        || !stable(&after_path, &path_metadata)
        || after_path.file_type().is_symlink()
        || handle_file_id(&file).ok()? != identity
        || regular_file_id(&path, false).ok()? != (identity, 1)
        || !is_single_link_handle(&file).ok()?
    {
        return None;
    }
    Some(payload)
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use crate::sfrs_token_vectors::NoEnvHost;

    #[test]
    fn existing_locked_service_preserves_static_body_files_and_rejects_aliases() {
        let root = std::env::temp_dir().join(format!(
            "guard-pr-body-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("pr-body.md");
        let content = b"PR body with a bounded public change description";
        fs::write(&path, content).unwrap();
        let host = NoEnvHost;
        let ctx = Ctx::new(&host, "/", "/");
        let candidate = PyPath::new(&path.to_string_lossy());
        assert_eq!(
            read_controlled_body(&candidate, &ctx).as_deref(),
            Some(content.as_slice())
        );
        let alias = root.join("alias.md");
        fs::hard_link(&path, &alias).unwrap();
        assert!(read_controlled_body(&candidate, &ctx).is_none());
        fs::remove_file(&alias).unwrap();
        fs::write(&path, []).unwrap();
        assert!(read_controlled_body(&candidate, &ctx).is_none());
        fs::remove_dir_all(&root).unwrap();
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use crate::codex_output_env::{GitCheck, GitRun, InspectionHost};
    use std::os::unix::fs::PermissionsExt;

    /// A host that answers the two questions this check asks of its caller:
    /// the real owner uid, and whether the body text holds a secret.
    struct BodyHost {
        secret: bool,
        uid: u32,
    }

    /// The uid that owns a path the test itself created, which is the uid the
    /// check must accept. The crate forbids `unsafe_code`, so the owner is read
    /// from the filesystem rather than from `getuid`.
    fn owner_uid(path: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().uid()
    }

    impl InspectionHost for BodyHost {
        fn env(&self, _: &str) -> Option<String> {
            None
        }
        fn current_uid(&self) -> Option<u32> {
            Some(self.uid)
        }
        fn secret_content_found(&self, _: &str, _: bool) -> bool {
            self.secret
        }
        fn git_executable(&self) -> Option<String> {
            None
        }
        fn git_safety(&self, _: GitCheck, _: Option<&str>, _: &[String]) -> bool {
            false
        }
        fn git_binary_trusted(&self, _: &str, _: &str) -> bool {
            false
        }
        fn run_git(&self, _: &str, _: &[String], _: &str) -> GitRun {
            GitRun::Failed("body-file test host does not run git")
        }
    }

    /// A fresh private directory, the shape `tmp_path` has in the retired
    /// Python suite.
    fn scratch(label: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "guard-pr-body-{label}-{}-{}",
            std::process::id(),
            crate::unique_nanos::unique_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::canonicalize(&root).unwrap()
    }

    fn is_safe(operand: &str, cwd: &Path, home: &Path) -> bool {
        let host = BodyHost {
            secret: false,
            uid: owner_uid(cwd),
        };
        let ctx = Ctx::new(&host, "/", "/");
        github_pr_body_file_is_safe(operand, Some(cwd), Some(home), &ctx)
    }

    #[test]
    fn bounded_owner_controlled_markdown_is_accepted_for_both_line_endings() {
        let root = scratch("newline");
        for (label, payload) in [
            ("lf", "## Summary\n- Focused change.\n"),
            ("crlf", "## Summary\r\n- Focused change.\r\n"),
        ] {
            let body = root.join(format!("{label}-pr-body.md"));
            fs::write(&body, payload).unwrap();
            assert!(
                is_safe(&body.to_string_lossy(), &root, root.parent().unwrap()),
                "{label}"
            );
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn canonical_pr_body_names_are_accepted_and_other_markdown_is_not() {
        let root = scratch("names");
        for name in [
            "pr-body.md",
            "pr-body.markdown",
            "PR-BODY.MD",
            "PR_BODY.md",
            "PR_BODY_PROTECTION.md",
        ] {
            let body = root.join(name);
            fs::write(&body, "## Summary\n- Focused change.\n").unwrap();
            assert!(
                is_safe(&body.to_string_lossy(), &root, root.parent().unwrap()),
                "{name}"
            );
            fs::remove_file(&body).unwrap();
        }
        // An arbitrary name, and a name that only carries the marker as a
        // suffix, stay outside the allowed shape.
        for name in ["internal-notes.md", "internal_notes_pr_body.md"] {
            let body = root.join(name);
            fs::write(&body, "Private planning notes.\n").unwrap();
            assert!(
                !is_safe(&body.to_string_lossy(), &root, root.parent().unwrap()),
                "{name}"
            );
            fs::remove_file(&body).unwrap();
        }
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_named_body_under_cascade_projects_is_authored_outside_the_working_tree() {
        let root = scratch("cascade");
        let home = root.join("home");
        let workspace = home.join("CascadeProjects").join("active-project");
        let body_directory = home.join("CascadeProjects").join("proposal-worktree");
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&body_directory).unwrap();
        // The check refuses group-writable directories and bodies, so a
        // permissive umask must not decide the outcome.
        for directory in [
            &home,
            &home.join("CascadeProjects"),
            &workspace,
            &body_directory,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let body = body_directory.join("PR_BODY_PROTECTION.md");
        fs::write(&body, "## Summary\n- Focused change.\n").unwrap();
        fs::set_permissions(&body, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(is_safe(
            "~/CascadeProjects/proposal-worktree/PR_BODY_PROTECTION.md",
            &workspace,
            &home
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn oversized_empty_and_sensitive_bodies_are_refused() {
        let root = scratch("bounds");
        let home = root.parent().unwrap();

        let oversized = root.join("pr-body.md");
        fs::write(&oversized, vec![b'x'; (MAX_PR_BODY_BYTES + 1) as usize]).unwrap();
        assert!(!is_safe(&oversized.to_string_lossy(), &root, home));

        fs::write(&oversized, []).unwrap();
        assert!(!is_safe(&oversized.to_string_lossy(), &root, home));

        let sensitive = root.join(".env-pr-body.md");
        fs::write(&sensitive, "## Summary\n- Focused change.\n").unwrap();
        assert!(!is_safe(&sensitive.to_string_lossy(), &root, home));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_padded_or_symlinked_operand_never_resolves() {
        let root = scratch("operand");
        let home = root.parent().unwrap();
        let body = root.join("pr-body.md");
        fs::write(&body, "## Summary\n- Focused change.\n").unwrap();
        let text = body.to_string_lossy().into_owned();

        for padding in [" ", "\t", "\n"] {
            assert!(
                !is_safe(&format!("{padding}{text}"), &root, home),
                "{padding:?}"
            );
        }

        let alias = root.join("alias-pr-body.md");
        std::os::unix::fs::symlink(&body, &alias).unwrap();
        assert!(!is_safe(&alias.to_string_lossy(), &root, home));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_shared_body_or_a_shared_parent_directory_is_refused() {
        let root = scratch("shared");
        let home = root.parent().unwrap();

        let shared_body = root.join("pr-body.md");
        fs::write(&shared_body, "## Summary\n- Focused change.\n").unwrap();
        fs::set_permissions(&shared_body, fs::Permissions::from_mode(0o620)).unwrap();
        assert!(!is_safe(&shared_body.to_string_lossy(), &root, home));
        fs::set_permissions(&shared_body, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(is_safe(&shared_body.to_string_lossy(), &root, home));

        let shared_directory = root.join("shared");
        fs::create_dir(&shared_directory).unwrap();
        fs::set_permissions(&shared_directory, fs::Permissions::from_mode(0o777)).unwrap();
        let nested = shared_directory.join("pr-body.md");
        fs::write(&nested, "## Summary\n- Focused change.\n").unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!is_safe(&nested.to_string_lossy(), &root, home));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn body_text_that_classifies_as_secret_is_refused() {
        let root = scratch("secret");
        let body = root.join("pr-body.md");
        fs::write(&body, "## Summary\n- Focused change.\n").unwrap();
        let host = BodyHost {
            secret: true,
            uid: owner_uid(&root),
        };
        let ctx = Ctx::new(&host, "/", "/");
        assert!(!github_pr_body_file_is_safe(
            &body.to_string_lossy(),
            Some(&root),
            Some(root.parent().unwrap()),
            &ctx
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_working_directory_or_home_fails_closed() {
        let root = scratch("missing");
        let body = root.join("pr-body.md");
        fs::write(&body, "## Summary\n- Focused change.\n").unwrap();
        let host = BodyHost {
            secret: false,
            uid: owner_uid(&root),
        };
        let ctx = Ctx::new(&host, "/", "/");
        let text = body.to_string_lossy().into_owned();
        assert!(!github_pr_body_file_is_safe(&text, None, Some(&root), &ctx));
        assert!(!github_pr_body_file_is_safe(&text, Some(&root), None, &ctx));
        fs::remove_dir_all(&root).unwrap();
    }
}
