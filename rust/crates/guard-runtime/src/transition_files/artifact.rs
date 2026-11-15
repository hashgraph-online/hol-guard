//! The pinned artifact and its launcher: `_artifact_digest`,
//! `_invocation_generation` and the `validate_regular_file` rules they apply.

use super::*;
use crate::transition_files::digest_cache;

/// What `_invocation_generation` compares before and after its checks.
#[cfg(unix)]
fn link_fingerprint(path: &Path) -> std::io::Result<Vec<i128>> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)?;
    Ok(vec![
        i128::from(meta.dev()),
        i128::from(meta.ino()),
        i128::from(meta.mode()),
        i128::from(meta.uid()),
        i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
    ])
}

#[cfg(windows)]
fn link_fingerprint(path: &Path) -> std::io::Result<Vec<i128>> {
    use std::os::windows::fs::MetadataExt;
    let stat = guard_runtime_windows_process::link_stat(path)?;
    let attributes = fs::symlink_metadata(path)?.file_attributes();
    Ok(vec![
        i128::from(stat.volume_serial),
        stat.file_index as i128,
        i128::from(attributes),
        i128::from(stat.last_write_time),
        i128::from(stat.creation_time),
    ])
}

#[cfg(unix)]
fn executable(path: &Path) -> bool {
    nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
}

#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    path.exists()
}

/// `_invocation_generation`: the authenticated launcher still resolves to
/// the artifact, keeping link semantics such as venv selection.
pub(crate) fn invocation_generation(
    target: &Path,
    identity: &Value,
    budget: &Budget,
) -> Step<Vec<i128>> {
    budget.forward()?;
    let path = PathBuf::from(identity["path"].as_str().unwrap_or_default());
    let changed = Fault::Transition("invocation_generation_changed");
    let unavailable = |_| Fault::Transition("invocation_dependency_unavailable");
    let before_meta = fs::symlink_metadata(&path).map_err(unavailable)?;
    let link = if before_meta.file_type().is_symlink() {
        let target = fs::read_link(&path).map_err(unavailable)?;
        Some(target.to_string_lossy().into_owned())
    } else {
        None
    };
    if !before_meta.file_type().is_symlink() && !before_meta.is_file() {
        return Err(Fault::Transition("invocation_dependency_invalid"));
    }
    let resolved = fs::canonicalize(&path).map_err(unavailable)?;
    if link.as_deref() != identity["link_target"].as_str()
        || plain(resolved) != target
        || !executable(&path)
    {
        return Err(changed);
    }
    let before = link_fingerprint(&path).map_err(unavailable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if Some(i64::from(before_meta.mode() & 0o777)) != whole(identity.get("mode"))
            || Some(i64::from(before_meta.uid())) != whole(identity.get("owner_uid"))
        {
            return Err(changed);
        }
    }
    let after = link_fingerprint(&path).map_err(unavailable)?;
    if before != after {
        return Err(changed);
    }
    budget.forward()?;
    Ok(after)
}

/// `validate_regular_file` for an artifact, any refusal folded into the one
/// reason `_artifact_digest` raises.
fn trusted_artifact(target: &Path, role: &str, ask: &Ask) -> Step<fs::Metadata> {
    let refused = || Fault::Transition("artifact_permissions_invalid");
    ask.budget.hook().map_err(|_| refused())?;
    let metadata = fs::symlink_metadata(target).map_err(|_| refused())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(refused());
    }
    let identity_ask = IdentityAsk {
        posix: cfg!(unix),
        current_uid: current_uid(),
        canonical_path: None,
        installed_python_package_file: crate::codex_hook_bridge_trust_files::under_package_root(
            target,
            &ask.package_roots,
        ),
    };
    let facts = FileFacts::of(target, &metadata);
    match permission_rules(&identity_ask, role, &facts, false) {
        Err(_) => return Err(refused()),
        Ok(None) => {}
        Ok(Some(question)) => {
            if !crate::codex_hook_bridge_trust_files::private_group(&question) {
                return Err(refused());
            }
        }
    }
    ask.budget.hook().map_err(|_| refused())?;
    Ok(metadata)
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(nix::unistd::getuid().as_raw())
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// `descriptor_fingerprint`: the identity a path's `lstat` and its open
/// descriptor's `fstat` agree on.
#[cfg(unix)]
fn descriptor_fingerprint(_target: &Path, meta: &fs::Metadata) -> std::io::Result<Vec<i128>> {
    use std::os::unix::fs::MetadataExt;
    Ok(vec![
        i128::from(meta.dev()),
        i128::from(meta.ino()),
        i128::from(meta.size()),
        i128::from(meta.mtime()) * 1_000_000_000 + i128::from(meta.mtime_nsec()),
        i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()),
        i128::from(meta.mode()),
        i128::from(meta.uid()),
        i128::from(meta.gid()),
    ])
}

#[cfg(windows)]
fn descriptor_fingerprint(_target: &Path, meta: &fs::Metadata) -> std::io::Result<Vec<i128>> {
    use std::os::windows::fs::MetadataExt;
    Ok(vec![
        i128::from(meta.file_size()),
        i128::from(meta.last_write_time()),
        i128::from(meta.file_attributes() & !0x20),
    ])
}

/// The path and descriptor fingerprints together, so Windows can add the
/// file id each side reports in its own way.
fn path_print(target: &Path, meta: &fs::Metadata) -> std::io::Result<(Vec<i128>, (u64, u128))> {
    Ok((
        descriptor_fingerprint(target, meta)?,
        path_identity(target)?,
    ))
}

fn file_print(
    target: &Path,
    file: &fs::File,
    meta: &fs::Metadata,
) -> std::io::Result<(Vec<i128>, (u64, u128))> {
    Ok((
        descriptor_fingerprint(target, meta)?,
        file_identity(file, meta)?,
    ))
}

/// `_artifact_digest`: hash the signed size through one owned descriptor.
pub(crate) fn artifact_digest(
    target: &Path,
    identity: &Value,
    mode: Option<u32>,
    ask: &Ask,
) -> Step<String> {
    let budget = &ask.budget;
    budget.forward()?;
    let role = identity["role"].as_str().unwrap_or("artifact");
    let trusted = trusted_artifact(target, role, ask)?;
    budget.forward()?;
    let unavailable = |_| Fault::Transition("artifact_dependency_unavailable");
    let file = open_no_follow(target, true).map_err(unavailable)?;
    let changed = || Fault::Transition("generation_changed");
    let opened = file.metadata().map_err(unavailable)?;
    if path_print(target, &trusted).map_err(unavailable)?
        != file_print(target, &file, &opened).map_err(unavailable)?
    {
        return Err(changed());
    }
    if !opened.is_file() || reparse_point(&opened) {
        return Err(Fault::Transition("artifact_dependency_invalid"));
    }
    if whole(identity.get("size")) != i64::try_from(opened.len()).ok() {
        return Err(changed());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if whole(identity.get("owner_uid")) != Some(i64::from(opened.uid())) {
            return Err(Fault::Transition("artifact_owner_changed"));
        }
        if Some(opened.mode() & 0o777) != mode {
            return Err(Fault::Transition("file_mode_changed"));
        }
    }
    #[cfg(not(unix))]
    let _ = mode;
    let started = std::time::SystemTime::now();
    let opened_print = descriptor_fingerprint(target, &opened).map_err(unavailable)?;
    if let Some(recorded) = digest_cache::recorded(target, &opened_print) {
        budget.forward()?;
        return Ok(recorded);
    }
    let mut digest = Sha256::new();
    let mut count = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        budget.forward()?;
        let read = (&file).read(&mut buffer).map_err(unavailable)?;
        budget.forward()?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > opened.len() {
            return Err(changed());
        }
        digest.update(&buffer[..read]);
    }
    let last = file.metadata().map_err(unavailable)?;
    let current = fs::symlink_metadata(target).map_err(unavailable)?;
    let final_print = file_print(target, &file, &last).map_err(unavailable)?;
    if count != opened.len()
        || file_print(target, &file, &opened).map_err(unavailable)? != final_print
        || final_print != path_print(target, &current).map_err(unavailable)?
    {
        return Err(changed());
    }
    budget.forward()?;
    let hex = format!("{:x}", digest.finalize());
    let settled_print = descriptor_fingerprint(target, &last).map_err(unavailable)?;
    digest_cache::record(target, settled_print, changed_ns(&last), started, &hex);
    Ok(hex)
}

#[cfg(unix)]
fn changed_ns(meta: &fs::Metadata) -> Option<i128> {
    use std::os::unix::fs::MetadataExt;
    Some(i128::from(meta.ctime()) * 1_000_000_000 + i128::from(meta.ctime_nsec()))
}

#[cfg(not(unix))]
fn changed_ns(_meta: &fs::Metadata) -> Option<i128> {
    None
}

#[cfg(windows)]
fn reparse_point(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_attributes() & REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn reparse_point(_meta: &fs::Metadata) -> bool {
    false
}
