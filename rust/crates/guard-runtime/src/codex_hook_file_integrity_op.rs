//! `runner_authority` kind `codex_hook_file_integrity`: live file checks for
//! Guard-managed Codex hooks, ported from `codex_hook_file_integrity`.
//!
//! Authenticated manifests establish the expected hook identity. These ops
//! describe trusted local files for a manifest and verify that the live
//! filesystem still matches an authenticated identity exactly. One fact stays
//! with the asking interpreter: which directories are its own package roots
//! (`package_roots`), since a group-writable file under one of them may still
//! be trusted when its group is private to its owner.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use crate::codex_hook_bridge_trust_files::{
    current_uid, executable, private_group, under_package_root, verify_executable_in,
    verify_regular_in,
};
use crate::codex_hook_file_identity_op::{open_regular, permission_rules, FileFacts, IdentityAsk};
use crate::codex_hook_manifest_build::{describe_executable, describe_regular};
use crate::runner_authority_op::{KindResult, ERR_INVALID};

const REPAIR: &str = "repair the installation.";

/// One integrity op: `{"ok": true}` with any answer it carries, or
/// `{"error": {"reason", "message"}}` for the file it refused.
pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args.as_object().ok_or(ERR_INVALID)?;
    let roots = package_roots(args)?;
    let outcome = match text(args, "op")? {
        "launch" => {
            return Ok(refusal(crate::codex_hook_launch_trust::launch(
                args, &roots,
            )))
        }
        "captured" => {
            return Ok(refusal(crate::codex_hook_launch_trust::captured(
                args, &roots,
            )))
        }
        "validate" => {
            let (path, role, executable_required) = target(args)?;
            validate(&path, role, executable_required, &roots).map(|_| Value::Null)
        }
        "describe_regular" => {
            let (path, role, executable_required) = target(args)?;
            describe_regular(&path, role, executable_required, &roots)
        }
        "describe_executable" => {
            let path = PathBuf::from(text(args, "path")?);
            describe_executable(&path, text(args, "role")?, &roots)
        }
        "verify_regular" => {
            verify_regular_in(field(args, "identity"), Some(&roots)).map(|()| Value::Null)
        }
        "verify_executable" => {
            verify_executable_in(field(args, "identity"), Some(&roots)).map(|()| Value::Null)
        }
        _ => return Err(ERR_INVALID),
    };
    Ok(match outcome {
        Ok(Value::Null) => json!({ "ok": true }),
        Ok(identity) => json!({ "ok": true, "identity": identity }),
        Err(reason) => json!({ "error": { "message": message(&reason), "reason": reason } }),
    })
}

/// A launch answer: `{"ok": true}` with any facts it carries, or the
/// refusal with the wording the asker reports.
fn refusal(outcome: Result<Value, crate::codex_hook_launch_trust::Refusal>) -> Value {
    match outcome {
        Ok(Value::Null) => json!({ "ok": true }),
        Ok(facts) => json!({ "ok": true, "facts": facts }),
        Err((reason, message)) => json!({ "error": { "message": message, "reason": reason } }),
    }
}

fn field<'a>(args: &'a Map<String, Value>, key: &str) -> &'a Value {
    args.get(key).unwrap_or(&Value::Null)
}

fn text<'a>(args: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    field(args, key)
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(ERR_INVALID)
}

fn target(args: &Map<String, Value>) -> Result<(PathBuf, &str, bool), &'static str> {
    let executable_required = field(args, "executable_required")
        .as_bool()
        .ok_or(ERR_INVALID)?;
    Ok((
        PathBuf::from(text(args, "path")?),
        text(args, "role")?,
        executable_required,
    ))
}

fn package_roots(args: &Map<String, Value>) -> Result<Vec<PathBuf>, &'static str> {
    match args.get("package_roots") {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(PathBuf::from).ok_or(ERR_INVALID))
            .collect(),
        Some(_) => Err(ERR_INVALID),
    }
}

fn refused(role: &str, kind: &str) -> String {
    format!("codex_hook_{role}_{kind}")
}

/// What a path's `lstat` says about the file it names, for telling a file that
/// was replaced while it was judged from one that was not.
#[cfg(unix)]
fn fingerprint(metadata: &fs::Metadata) -> Vec<u64> {
    use std::os::unix::fs::MetadataExt;
    vec![
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        (metadata.mtime() as u64).wrapping_mul(1_000_000_000) + metadata.mtime_nsec() as u64,
        u64::from(metadata.mode()),
        u64::from(metadata.uid()),
    ]
}

/// Off POSIX the volume and file index are not stable Rust API; the size,
/// last write, creation time and attributes still change when a file is replaced.
#[cfg(windows)]
fn fingerprint(metadata: &fs::Metadata) -> Vec<u64> {
    use std::os::windows::fs::MetadataExt;
    vec![
        metadata.file_size(),
        metadata.last_write_time(),
        metadata.creation_time(),
        u64::from(metadata.file_attributes()),
    ]
}

/// `validate_regular_file`, bracketed: the name's `lstat` before the checks
/// must still describe it after them, so a file replaced while it was judged
/// is `codex_hook_{role}_hash_mismatch`, and one that vanished
/// `codex_hook_{role}_missing`.
fn validate(
    path: &Path,
    role: &str,
    executable_required: bool,
    package_roots: &[PathBuf],
) -> Result<(), String> {
    let before = fs::symlink_metadata(path).ok().map(|m| fingerprint(&m));
    admit(path, role, executable_required, package_roots)?;
    let after = fs::symlink_metadata(path).map_err(|_| refused(role, "missing"))?;
    if before != Some(fingerprint(&after)) {
        return Err(refused(role, "hash_mismatch"));
    }
    Ok(())
}

/// `validate_regular_file`: `path` names a regular file, not a symlink, that
/// only its owner (or a group private to the owner, where Guard trusts that)
/// may write, and that may run when `executable_required`. Answers the facts
/// and the handle the checks read, so nothing is read through the name again.
pub(crate) fn admit(
    path: &Path,
    role: &str,
    executable_required: bool,
    package_roots: &[PathBuf],
) -> Result<(FileFacts, fs::File), String> {
    let named = fs::symlink_metadata(path).map_err(|_| refused(role, "missing"))?;
    if named.file_type().is_symlink() || !named.file_type().is_file() {
        return Err(refused(role, "not_regular"));
    }
    let (facts, file) = open_regular(path).ok_or_else(|| refused(role, "not_regular"))?;
    let ask = IdentityAsk {
        posix: cfg!(unix),
        current_uid: current_uid(),
        canonical_path: None,
        installed_python_package_file: under_package_root(path, package_roots),
    };
    let unsafe_group =
        |question: &Option<Value>| question.as_ref().is_some_and(|q| !private_group(q));
    match permission_rules(&ask, role, &facts, executable_required) {
        Ok(question) if unsafe_group(&question) => return Err(refused(role, "permissions_unsafe")),
        Ok(_) => {}
        Err((_, question)) if unsafe_group(&question) => {
            return Err(refused(role, "permissions_unsafe"))
        }
        Err((kind, _)) => return Err(refused(role, kind)),
    }
    // Off POSIX the execute bit has no meaning; `os.access(path, X_OK)` is
    // what Python asks there.
    if !cfg!(unix) && executable_required && !executable(path) {
        return Err(refused(role, "not_executable"));
    }
    Ok((facts, file))
}

/// The status wording `codex_hook_file_integrity` gives each refusal.
pub(crate) fn message(reason: &str) -> String {
    if reason == "codex_hook_file_identity_invalid" {
        return format!("The Codex hook manifest has an invalid packaged-file identity; {REPAIR}");
    }
    const KINDS: [(&str, &str); 15] = [
        ("invocation_mode_mismatch", "invocation permissions changed"),
        ("invocation_owner_mismatch", "invocation owner changed"),
        ("invocation_type_mismatch", "invocation type changed"),
        ("symlink_target_mismatch", "symlink target changed"),
        ("target_path_mismatch", "target changed"),
        ("permissions_unsafe", "is writable by another user"),
        ("owner_untrusted", "has an unexpected owner"),
        ("identity_invalid", "identity is invalid"),
        ("not_executable", "is not executable"),
        ("path_mismatch", "path is no longer canonical"),
        ("mode_mismatch", "permissions changed"),
        ("hash_mismatch", "content changed"),
        ("owner_mismatch", "owner changed"),
        ("not_regular", "must be a regular file, not a symlink"),
        ("missing", "is missing"),
    ];
    let rest = reason.strip_prefix("codex_hook_").unwrap_or(reason);
    for (kind, what) in KINDS {
        if let Some(role) = rest
            .strip_suffix(kind)
            .and_then(|head| head.strip_suffix('_'))
        {
            return format!("The Codex hook {role} {what}; {REPAIR}");
        }
    }
    format!("Guard could not verify the Codex hook {rest}; {REPAIR}")
}

#[cfg(test)]
#[path = "codex_hook_file_integrity_op_tests.rs"]
mod tests;
