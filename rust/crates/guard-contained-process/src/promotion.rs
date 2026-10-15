use super::*;

const LIMIT: usize = 256 * 1024 * 1024;

fn same_object(left: &Identity, right: &Identity) -> bool {
    #[cfg(unix)]
    {
        left.device == right.device && left.inode == right.inode
    }
    #[cfg(windows)]
    {
        left.file_id == right.file_id
    }
}
#[cfg(unix)]
fn matches(file: &ReadFile, expected: (&Identity, &str)) -> bool {
    same_object(&file.identity, expected.0) && file.digest == expected.1
}

/// Existing-target publication is transactional, not a filesystem compare-and-
/// swap: a failed exchange can briefly expose the new bytes. Never attest that
/// exchange unless the displaced object matches. Recovery names containing
/// raced user objects are deliberately retained, never recursively cleaned.
///
/// The recovery directory is created mode 0700, so only the same user can
/// reach its names. POSIX has no unlink that checks identity, so on Unix the
/// final discard of a staged or displaced name is a check followed by an
/// unlink: a same-user writer that renames its own object onto that name in
/// the window between the two is removed with it. The "retain raced objects"
/// guarantee therefore holds against races before the check, and is
/// best-effort against a same-user writer that targets the check-to-unlink
/// window. It never widens authority: the unlink only ever acts inside the
/// private recovery directory, never on the published target.
pub(super) fn replace(
    root: &Directory,
    path: &Path,
    expected: Option<(&Identity, &str)>,
    bytes: &[u8],
) -> io::Result<()> {
    relative_components(path)?;
    let parent_path = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = root.directory(parent_path)?;
    let name = path.file_name().ok_or_else(changed)?;
    let before = match root.read(path, LIMIT) {
        Ok(read) => Some(read),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    match (expected, before.as_ref()) {
        (Some((id, digest)), Some(read)) if id == &read.identity && digest == read.digest => {}
        (None, None) => {}
        _ => return Err(changed()),
    }
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).map_err(io::Error::other)?;
    let recovery_name = OsString::from(format!(
        ".guard-promotion-recovery-{}",
        hex::encode(entropy)
    ));
    parent.mkdir_all(Path::new(&recovery_name))?;
    let recovery = parent.directory(Path::new(&recovery_name))?;
    #[cfg(windows)]
    {
        let operation = (|| {
            recovery.create(Path::new("new"), bytes, false)?;
            let written = recovery.read(Path::new("new"), LIMIT)?;
            parent.verify()?;
            crate::windows::promote_transaction(&parent, name, &recovery, expected, &written)
        })();
        let cleanup = finish_recovery(&parent, &recovery_name, recovery);
        operation.and(cleanup)
    }
    #[cfg(unix)]
    {
        let mut staged = None;
        let operation = (|| {
            recovery.create(Path::new("new"), bytes, false)?;
            let written = recovery.read(Path::new("new"), LIMIT)?;
            staged = Some((written.identity.clone(), written.digest.clone()));
            publish_staged(
                root,
                path,
                &parent,
                name,
                &recovery,
                before.as_ref(),
                expected,
                &written,
            )
        })();
        // Every exit after the recovery directory exists reaches this point.
        // Staged bytes we wrote ourselves are discarded when still unchanged;
        // displaced or raced user objects are never matched and stay retained.
        if let Some((id, digest)) = staged.as_ref() {
            if recovery
                .read(Path::new("new"), LIMIT)
                .is_ok_and(|file| matches(&file, (id, digest)))
            {
                let _ = recovery.unlink(Path::new("new"), false);
            }
        }
        let cleanup = finish_recovery(&parent, &recovery_name, recovery);
        let durable = sync_directory(&parent);
        let verified = parent.verify();
        operation.and(cleanup).and(durable).and(verified)
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn publish_staged(
    root: &Directory,
    path: &Path,
    parent: &Directory,
    name: &OsStr,
    recovery: &Directory,
    before: Option<&ReadFile>,
    expected: Option<(&Identity, &str)>,
    written: &ReadFile,
) -> io::Result<()> {
    if let Some(before) = before {
        let original = root.open_file(path)?;
        if !same_object(&identity(&original)?, &before.identity) {
            return Err(changed());
        }
        let new = recovery.open_file(Path::new("new"))?;
        if unsafe {
            libc::fchmod(
                new.as_raw_fd(),
                (original.metadata()?.mode() & 0o777) as libc::mode_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    parent.verify()?;
    if let Some(expected) = expected {
        exchange(recovery, OsStr::new("new"), parent, name)?;
        let displaced = recovery.read(Path::new("new"), LIMIT);
        let current = parent.read(Path::new(name), LIMIT);
        if displaced.as_ref().is_ok_and(|file| matches(file, expected))
            && current
                .as_ref()
                .is_ok_and(|file| matches(file, (&written.identity, &written.digest)))
        {
            // Displaced bytes are the exact old target authorized for
            // replacement. The private recovery directory holds their name.
            recovery.unlink(Path::new("new"), false)?;
            sync_directory(recovery)?;
            sync_directory(parent)?;
            Ok(())
        } else {
            rollback(parent, name, recovery, written)?;
            sync_directory(recovery)?;
            sync_directory(parent)?;
            Err(changed())
        }
    } else {
        publish_new(recovery, OsStr::new("new"), parent, name)?;
        sync_directory(recovery)?;
        sync_directory(parent)?;
        if !parent
            .read(Path::new(name), LIMIT)
            .is_ok_and(|file| matches(&file, (&written.identity, &written.digest)))
        {
            return Err(changed());
        }
        Ok(())
    }
}

/// Directory entries changed by exchange/link/unlink are only durable once the
/// containing directory itself reaches stable storage. Plain fsync is used so
/// macOS does not need F_FULLFSYNC semantics on a directory descriptor.
#[cfg(unix)]
fn sync_directory(directory: &Directory) -> io::Result<()> {
    loop {
        if unsafe { libc::fsync(directory.handle().as_raw_fd()) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn finish_recovery(parent: &Directory, name: &OsStr, recovery: Directory) -> io::Result<()> {
    // No remove_tree: a second racing writer may have put its bytes here.
    let empty = recovery.entries(Path::new("."), 50_000)?.is_empty();
    drop(recovery);
    if empty {
        parent.unlink(Path::new(name), true)?;
    }
    Ok(())
}

#[cfg(unix)]
fn exchange(
    left: &Directory,
    left_name: &OsStr,
    right: &Directory,
    right_name: &OsStr,
) -> io::Result<()> {
    left.verify()?;
    right.verify()?;
    let left_name = cstr(left_name)?;
    let right_name = cstr(right_name)?;
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            left.file.as_raw_fd(),
            left_name.as_ptr(),
            right.file.as_raw_fd(),
            right_name.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    #[cfg(target_os = "macos")]
    let status = unsafe {
        libc::renameatx_np(
            left.file.as_raw_fd(),
            left_name.as_ptr(),
            right.file.as_raw_fd(),
            right_name.as_ptr(),
            libc::RENAME_SWAP,
        )
    } as libc::c_long;
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn publish_new(
    source: &Directory,
    name: &OsStr,
    target: &Directory,
    target_name: &OsStr,
) -> io::Result<()> {
    let name = cstr(name)?;
    let target_name = cstr(target_name)?;
    if unsafe {
        libc::linkat(
            source.file.as_raw_fd(),
            name.as_ptr(),
            target.file.as_raw_fd(),
            target_name.as_ptr(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::unlinkat(source.file.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn rollback(
    parent: &Directory,
    name: &OsStr,
    recovery: &Directory,
    written: &ReadFile,
) -> io::Result<()> {
    // If another writer has replaced/changed the published target, do not
    // overwrite it. The displaced user's object remains in recovery/new.
    let current = parent.read(Path::new(name), LIMIT);
    if !current
        .as_ref()
        .is_ok_and(|file| matches(file, (&written.identity, &written.digest)))
    {
        return Ok(());
    }
    exchange(recovery, OsStr::new("new"), parent, name)?;
    // A second replacement between the check and reverse exchange is now in
    // recovery/new. Only our own unchanged bytes may be discarded; user bytes,
    // including modifications to our inode, are retained for recovery.
    if recovery
        .read(Path::new("new"), LIMIT)
        .is_ok_and(|file| matches(&file, (&written.identity, &written.digest)))
    {
        recovery.unlink(Path::new("new"), false)?;
    }
    Ok(())
}

pub(super) fn remove(root: &Directory, path: &Path, expected: (&Identity, &str)) -> io::Result<()> {
    relative_components(path)?;
    let parent_path = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = root.directory(parent_path)?;
    let name = path.file_name().ok_or_else(changed)?;
    let before = parent.read(Path::new(name), LIMIT)?;
    if before.identity != *expected.0 || before.digest != expected.1 {
        return Err(changed());
    }
    #[cfg(windows)]
    {
        crate::windows::remove_bound_file(&parent, name, expected)
    }
    #[cfg(unix)]
    {
        let (recovery_name, recovery) = quarantine(&parent)?;
        if let Err(error) = move_exclusive(&parent, name, &recovery, OsStr::new("old")) {
            finish_recovery(&parent, &recovery_name, recovery)?;
            return Err(error);
        }
        let operation = match recovery.read(Path::new("old"), LIMIT) {
            Ok(file) if matches(&file, expected) => recovery.unlink(Path::new("old"), false),
            _ => {
                // Restore only into an absent target. An intervening user
                // replacement wins; the displaced object stays in recovery.
                let _ = move_exclusive(&recovery, OsStr::new("old"), &parent, name);
                Err(changed())
            }
        };
        let synced = sync_directory(&recovery);
        finish_recovery(&parent, &recovery_name, recovery)?;
        let synced = synced.and(sync_directory(&parent));
        parent.verify()?;
        operation.and(synced)
    }
}

pub(super) fn remove_directory(
    root: &Directory,
    path: &Path,
    expected: &Identity,
) -> io::Result<()> {
    relative_components(path)?;
    let parent_path = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = root.directory(parent_path)?;
    let name = path.file_name().ok_or_else(changed)?;
    {
        let directory = parent.directory(Path::new(name))?;
        if !same_object(&identity(directory.handle())?, expected)
            || !directory.entries(Path::new("."), 1)?.is_empty()
        {
            return Err(changed());
        }
    }
    #[cfg(windows)]
    {
        crate::windows::remove_bound_directory(&parent, name, expected)
    }
    #[cfg(unix)]
    {
        let (recovery_name, recovery) = quarantine(&parent)?;
        if let Err(error) = move_exclusive(&parent, name, &recovery, OsStr::new("old")) {
            finish_recovery(&parent, &recovery_name, recovery)?;
            return Err(error);
        }
        let displaced = recovery.directory(Path::new("old"));
        let valid = displaced.as_ref().is_ok_and(|directory| {
            identity(directory.handle()).is_ok_and(|id| same_object(&id, expected))
                && directory
                    .entries(Path::new("."), 1)
                    .is_ok_and(|names| names.is_empty())
        });
        drop(displaced);
        let operation = if valid {
            recovery.unlink(Path::new("old"), true)
        } else {
            let _ = move_exclusive(&recovery, OsStr::new("old"), &parent, name);
            Err(changed())
        };
        let synced = sync_directory(&recovery);
        finish_recovery(&parent, &recovery_name, recovery)?;
        let synced = synced.and(sync_directory(&parent));
        parent.verify()?;
        operation.and(synced)
    }
}

#[cfg(unix)]
fn quarantine(parent: &Directory) -> io::Result<(OsString, Directory)> {
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).map_err(io::Error::other)?;
    let name = OsString::from(format!(
        ".guard-promotion-recovery-{}",
        hex::encode(entropy)
    ));
    parent.mkdir_all(Path::new(&name))?;
    let directory = parent.directory(Path::new(&name))?;
    Ok((name, directory))
}
#[cfg(unix)]
fn move_exclusive(
    source: &Directory,
    name: &OsStr,
    target: &Directory,
    target_name: &OsStr,
) -> io::Result<()> {
    source.verify()?;
    target.verify()?;
    let name = cstr(name)?;
    let target_name = cstr(target_name)?;
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            source.handle().as_raw_fd(),
            name.as_ptr(),
            target.handle().as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::renameatx_np(
            source.handle().as_raw_fd(),
            name.as_ptr(),
            target.handle().as_raw_fd(),
            target_name.as_ptr(),
            libc::RENAME_EXCL,
        )
    } as libc::c_long;
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
#[path = "promotion_tests.rs"]
mod tests;
