//! The file checks behind the Codex hook launch authentication: recorded
//! file identities, the recorded interpreter, and canonical path spelling.

use std::fs;
use std::path::{Component, Path, PathBuf};

use serde_json::Value;

use crate::codex_hook_file_identity_op::{identity_answer, IdentityAsk};

/// Why a file is not private to the current user.
pub(super) enum Private {
    Owner,
    Mode,
}

/// `Path.resolve(strict=False)`: links resolved in the longest existing
/// prefix, the missing tail appended as written.
pub(super) fn canonical(path: &Path) -> PathBuf {
    let mut existing = path;
    let mut tail = Vec::new();
    loop {
        if let Ok(resolved) = fs::canonicalize(existing) {
            let mut resolved = plain(resolved);
            for name in tail.iter().rev() {
                resolved.push(name);
            }
            return resolved;
        }
        match (existing.components().next_back(), existing.parent()) {
            (Some(Component::Normal(name)), Some(parent)) => {
                tail.push(name);
                existing = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Windows `canonicalize` answers in verbatim form; identities record the
/// ordinary spelling Python uses.
#[cfg(windows)]
fn plain(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => path,
    }
}

#[cfg(not(windows))]
fn plain(path: PathBuf) -> PathBuf {
    path
}

/// A file only its owner may read or write, owned by the current user.
#[cfg(unix)]
pub(super) fn private_to_owner(metadata: &fs::Metadata) -> Result<(), Private> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != nix::unistd::getuid().as_raw() {
        return Err(Private::Owner);
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(Private::Mode);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn private_to_owner(_metadata: &fs::Metadata) -> Result<(), Private> {
    Ok(())
}

fn ask_for(canonical_path: Option<&str>) -> IdentityAsk<'_> {
    IdentityAsk {
        posix: cfg!(unix),
        current_uid: current_uid(),
        canonical_path,
        installed_python_package_file: true,
    }
}

#[cfg(unix)]
fn current_uid() -> Option<u32> {
    Some(nix::unistd::getuid().as_raw())
}

#[cfg(not(unix))]
fn current_uid() -> Option<u32> {
    None
}

/// `verify_regular_file_identity`, reason codes included.
pub(super) fn verify_regular(identity: &Value) -> Result<(), String> {
    let spelled = identity
        .get("path")
        .and_then(Value::as_str)
        .map(|path| canonical(Path::new(path)).to_string_lossy().into_owned());
    let answer = identity_answer(&ask_for(spelled.as_deref()), identity);
    let field = |name: &str| answer.get(name).and_then(Value::as_str).unwrap_or("");
    if field("outcome") == "verified" {
        return match answer.get("private_group_question") {
            Some(question) if !private_group(question) => {
                Err(format!("codex_hook_{}_permissions_unsafe", field("role")))
            }
            _ => Ok(()),
        };
    }
    Err(format!("codex_hook_{}_{}", field("role"), field("kind")))
}

/// `_owner_private_group`: the group-write bit is safe only when the group
/// is the owner's own: their primary group, named after them, and listing
/// no one else.
#[cfg(unix)]
fn private_group(question: &Value) -> bool {
    use nix::unistd::{Gid, Group, Uid, User};
    let number = |name: &str| {
        question
            .get(name)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    let (Some(owner), Some(gid)) = (number("owner_uid"), number("group_gid")) else {
        return false;
    };
    let (Ok(Some(user)), Ok(Some(group))) = (
        User::from_uid(Uid::from_raw(owner)),
        Group::from_gid(Gid::from_raw(gid)),
    ) else {
        return false;
    };
    user.gid.as_raw() == gid
        && group.name == user.name
        && group.mem.iter().all(|member| member == &user.name)
}

#[cfg(not(unix))]
fn private_group(_question: &Value) -> bool {
    false
}

/// `verify_executable_file_identity`: the recorded invocation path, link and
/// mode, and the regular file it resolves to.
pub(super) fn verify_executable(identity: &Value) -> Result<(), String> {
    let role = identity
        .get("role")
        .and_then(Value::as_str)
        .filter(|role| !role.is_empty())
        .unwrap_or("interpreter");
    let reason = |kind: &str| format!("codex_hook_{role}_{kind}");
    let invocation = identity
        .get("invocation_path")
        .and_then(Value::as_str)
        .map(Path::new)
        .filter(|path| path.is_absolute());
    let mode = identity.get("invocation_mode").and_then(Value::as_u64);
    let (Some(invocation), Some(mode)) = (invocation, mode) else {
        return Err(reason("identity_invalid"));
    };
    let metadata = fs::symlink_metadata(invocation).map_err(|_| reason("missing"))?;
    invocation_facts(&metadata, mode, identity).map_err(reason)?;
    match identity.get("link_target") {
        None | Some(Value::Null) => {
            if !metadata.file_type().is_file() {
                return Err(reason("invocation_type_mismatch"));
            }
        }
        Some(Value::String(expected)) => {
            if !metadata.file_type().is_symlink() {
                return Err(reason("invocation_type_mismatch"));
            }
            let target =
                fs::read_link(invocation).map_err(|_| reason("symlink_target_mismatch"))?;
            if target.to_str() != Some(expected.as_str()) {
                return Err(reason("symlink_target_mismatch"));
            }
        }
        Some(_) => return Err(reason("invocation_type_mismatch")),
    }
    if !executable(invocation) {
        return Err(reason("not_executable"));
    }
    let target = identity.get("target").unwrap_or(&Value::Null);
    verify_regular(target)?;
    let resolved = canonical(invocation);
    if target.get("path").and_then(Value::as_str) != resolved.to_str() {
        return Err(reason("target_path_mismatch"));
    }
    Ok(())
}

#[cfg(unix)]
fn invocation_facts(
    metadata: &fs::Metadata,
    mode: u64,
    identity: &Value,
) -> Result<(), &'static str> {
    use std::os::unix::fs::MetadataExt;
    if u64::from(metadata.mode() & 0o7777) != mode {
        return Err("invocation_mode_mismatch");
    }
    let owner = identity.get("invocation_owner_uid").and_then(Value::as_u64);
    if owner.is_some_and(|owner| owner != u64::from(metadata.uid())) {
        return Err("invocation_owner_mismatch");
    }
    Ok(())
}

#[cfg(not(unix))]
fn invocation_facts(
    metadata: &fs::Metadata,
    mode: u64,
    _identity: &Value,
) -> Result<(), &'static str> {
    // Python reports `stat.S_IMODE` of a Windows file: 0o666 or 0o444 by the
    // read-only attribute, plus 0o111 for an executable suffix.
    let _ = (metadata, mode);
    Ok(())
}

#[cfg(unix)]
fn executable(path: &Path) -> bool {
    nix::unistd::access(path, nix::unistd::AccessFlags::X_OK).is_ok()
}

#[cfg(not(unix))]
fn executable(path: &Path) -> bool {
    path.exists()
}
