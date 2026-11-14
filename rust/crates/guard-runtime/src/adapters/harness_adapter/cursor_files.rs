//! The file work behind Cursor's hooks: owner-only writes under an authorized
//! parent, the attestation key the hook signs observer proofs with, and the
//! live-script path checks.

use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use super::{Ctx, Failure, Step};
use crate::copilot_detect::universal_newlines;

const SECRET_MAX_BYTES: usize = 4096;

pub(super) fn os(error: std::io::Error) -> Failure {
    Failure::Os(error.to_string())
}

/// `write_text_at_authorized_path`: replace `path` atomically beneath its
/// resolved parent, never following a final link.
pub(super) fn write_authorized(ctx: &Ctx, path: &Path, bytes: &[u8]) -> Step<()> {
    let path = ctx.absolute(path);
    let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(Failure::Os("Cursor path has no parent directory".into()));
    };
    fs::create_dir_all(parent).map_err(os)?;
    let target = fs::canonicalize(parent).map_err(os)?.join(name);
    super::authorized_write::write_beneath_parent(&target, bytes).map_err(os)
}

pub(super) fn unlink(ctx: &Ctx, path: &Path) -> Step<()> {
    fs::remove_file(ctx.absolute(path)).map_err(os)
}

pub(super) fn unlink_file(ctx: &Ctx, path: &Path) -> Step<()> {
    if ctx.absolute(path).is_file() {
        unlink(ctx, path)?;
    }
    Ok(())
}

/// `read_text(encoding="utf-8")`: `None` on an OS error, newlines folded.
pub(super) fn read_text(ctx: &Ctx, path: &Path, label: &str) -> Step<Option<String>> {
    match fs::read(ctx.absolute(path)) {
        Ok(bytes) => Ok(Some(universal_newlines(super::kimi::utf8(bytes, label)?))),
        Err(_) => Ok(None),
    }
}

/// `restore_from_backup`: put back what the backup holds; whether it did.
pub(super) fn restore(ctx: &Ctx, backup: &Path, target: &Path, label: &str) -> Step<bool> {
    let (plan, content) = super::files::backup_plan(ctx, backup, target, label)?;
    match (plan["action"].as_str(), content) {
        (Some("write"), Some(content)) => write_authorized(ctx, target, content.as_bytes())?,
        (Some("unlink"), _) => unlink(ctx, target)?,
        _ => {}
    }
    Ok(plan["restored"].as_bool() == Some(true))
}

/// `_is_managed_cursor_hook_script`: named like Guard's script, in a Cursor
/// hooks directory or Guard's managed copy.
pub(super) fn managed_script_name(path: &Path) -> bool {
    let parts: Vec<String> = path
        .components()
        .map(|part| part.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    let script = super::cursor::SCRIPT_NAME.to_lowercase();
    if parts.last() != Some(&script) || parts.iter().any(|part| part == "..") || parts.len() < 3 {
        return false;
    }
    let parents = &parts[parts.len() - 3..parts.len() - 1];
    parents == [".cursor", "hooks"] || parents == ["managed", "cursor"]
}

/// `_cursor_hook_path_contains_symlink`: an error counts as a link.
fn contains_symlink(ctx: &Ctx, path: &Path) -> bool {
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        match fs::symlink_metadata(ctx.absolute(&current)) {
            Ok(meta) if meta.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound || not_a_directory(&error) => {}
            Err(_) => return true,
        }
    }
    current.as_os_str().is_empty()
}

fn not_a_directory(error: &std::io::Error) -> bool {
    error.kind() == ErrorKind::NotADirectory
}

/// A live hook script Guard would run: managed name, no link, a file.
pub(super) fn live_script(ctx: &Ctx, path: &Path) -> bool {
    managed_script_name(path) && !contains_symlink(ctx, path) && ctx.absolute(path).is_file()
}

/// `prune_empty_project_cursor_dir`: drop the emptied legacy project dirs.
pub(super) fn prune_project_dirs(ctx: &Ctx, workspace: &Path) {
    let cursor = ctx.absolute(&workspace.join(".cursor"));
    let hooks = cursor.join("hooks");
    if hooks.is_dir() {
        match fs::read_dir(&hooks) {
            Ok(mut entries) => {
                if entries.next().is_none() && fs::remove_dir(&hooks).is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
    if let Ok(mut entries) = fs::read_dir(&cursor) {
        if cursor.is_dir() && entries.next().is_none() {
            let _ = fs::remove_dir(&cursor);
        }
    }
}

fn unlink_quietly(path: &Path) {
    let _ = fs::remove_file(path);
}

/// `_read_private_attestation_secret`: a key the resident can verify.
#[cfg(unix)]
fn private_secret(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let uid = nix::unistd::geteuid().as_raw();
    let info = fs::symlink_metadata(path).ok()?;
    if !info.file_type().is_file() || info.uid() != uid {
        unlink_quietly(path);
        return None;
    }
    if info.mode() & 0o077 != 0
        && fs::set_permissions(path, fs::Permissions::from_mode(0o600)).is_err()
    {
        unlink_quietly(path);
        return None;
    }
    let Ok(file) = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    else {
        unlink_quietly(path);
        return None;
    };
    let mut existing = Vec::new();
    (&file)
        .take(SECRET_MAX_BYTES as u64 + 1)
        .read_to_end(&mut existing)
        .ok()?;
    let confirmed = file.metadata().ok()?;
    if !confirmed.file_type().is_file() || confirmed.uid() != uid || confirmed.mode() & 0o077 != 0 {
        unlink_quietly(path);
        return None;
    }
    if existing.is_empty() || existing.len() > SECRET_MAX_BYTES {
        unlink_quietly(path);
        return None;
    }
    Some(existing)
}

#[cfg(not(unix))]
fn private_secret(path: &Path) -> Option<Vec<u8>> {
    let info = fs::symlink_metadata(path).ok()?;
    if !info.file_type().is_file() {
        return None;
    }
    let mut existing = Vec::new();
    fs::File::open(path)
        .ok()?
        .take(SECRET_MAX_BYTES as u64 + 1)
        .read_to_end(&mut existing)
        .ok()?;
    if existing.is_empty() || existing.len() > SECRET_MAX_BYTES {
        unlink_quietly(path);
        return None;
    }
    Some(existing)
}

#[cfg(unix)]
fn write_secret(path: &Path, generated: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let open = |create: bool| {
        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        if create {
            options.create_new(true);
        } else {
            options.truncate(true);
        }
        options.open(path)
    };
    let mut file = open(true).or_else(|_| open(false))?;
    let written = (|| {
        file.write_all(generated)?;
        file.flush()?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        if file.metadata()?.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::other("attestation key mode is not private"));
        }
        Ok(())
    })();
    if written.is_err() {
        unlink_quietly(path);
    }
    written
}

#[cfg(not(unix))]
fn write_secret(path: &Path, generated: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    let mut file = options
        .write(true)
        .create_new(true)
        .open(path)
        .or_else(|_| fs::OpenOptions::new().write(true).truncate(true).open(path))?;
    let written = file.write_all(generated).and_then(|()| file.flush());
    if written.is_err() {
        unlink_quietly(path);
    }
    written
}

/// `ensure_cursor_hook_attestation_secret`: keep a private key, or make one.
pub(super) fn ensure_secret(ctx: &Ctx, path: &Path) -> Step<()> {
    let path = ctx.absolute(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(os)?;
    }
    if private_secret(&path).is_some() {
        return Ok(());
    }
    let mut generated = [0u8; 32];
    getrandom::fill(&mut generated).map_err(|error| Failure::Os(error.to_string()))?;
    write_secret(&path, &generated).map_err(os)
}

/// The attestation key's bytes and whether its mode keeps it owner-only.
pub(super) fn secret_private(ctx: &Ctx, path: &Path) -> bool {
    if ctx.windows {
        return true;
    }
    super::files::mode(ctx, path).is_some_and(|mode| mode & 0o077 == 0)
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{symlink, PermissionsExt};

    use super::*;

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn a_loose_key_is_tightened_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("cursor-hook-attestation.key");
        fs::write(&key, b"existing-key-bytes").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            private_secret(&key).as_deref(),
            Some(&b"existing-key-bytes"[..])
        );
        assert_eq!(mode(&key), 0o600);
    }

    #[test]
    fn an_empty_key_is_discarded_for_a_new_one() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("cursor-hook-attestation.key");
        fs::write(&key, b"").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_secret(&key).is_none());
        assert!(!key.exists());
        write_secret(&key, &[7u8; 32]).unwrap();
        assert_eq!(fs::read(&key).unwrap(), [7u8; 32]);
        assert_eq!(mode(&key), 0o600);
    }

    #[test]
    fn a_symlinked_key_is_replaced_without_touching_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("cursor-hook-attestation.key");
        let target = dir.path().join("outside.key");
        fs::write(&target, b"outside-key").unwrap();
        symlink(&target, &key).unwrap();
        assert!(private_secret(&key).is_none());
        assert!(fs::symlink_metadata(&key).is_err());
        write_secret(&key, &[9u8; 32]).unwrap();
        assert!(!fs::symlink_metadata(&key).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"outside-key");
    }

    #[test]
    fn writing_a_key_never_follows_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("cursor-hook-attestation.key");
        let target = dir.path().join("outside.key");
        fs::write(&target, b"outside-key").unwrap();
        symlink(&target, &key).unwrap();
        assert!(write_secret(&key, b"replacement-key").is_err());
        assert_eq!(fs::read(&target).unwrap(), b"outside-key");
    }
}
