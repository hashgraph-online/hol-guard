//! Content-bind the file operands of a command.

use serde_json::{json, Value};

use super::context::Ctx;
use super::fs_path;

const MAX_BOUND_OPERANDS: usize = 16;
const MAX_BOUND_OPERAND_BYTES: u64 = 4_194_304;

/// The value part of an argument: `--flag=value` binds `value`.
pub(super) fn argument_value(argument: &str) -> &str {
    if argument.starts_with('-') {
        argument.split_once('=').map_or("", |(_, value)| value)
    } else {
        argument
    }
}

const EBADF: i32 = 9;
const ELOOP: i32 = if cfg!(target_os = "macos") { 62 } else { 40 };

/// Python's `Path.is_file`/`exists` ignore only these errors; any other (an
/// over-long name, a permission failure) is an operand that cannot be bound.
fn ignorable(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    ) || matches!(error.raw_os_error(), Some(code) if code == EBADF || code == ELOOP)
}

/// `Ok(None)` when the path is absent, `Err` when it cannot be examined.
fn probe(path: &str) -> Result<Option<std::fs::Metadata>, ()> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if ignorable(&error) => Ok(None),
        Err(_) => Err(()),
    }
}

/// Hash file operands (marking absent and non-file ones), or `None` when they
/// cannot be bound: too many, too large or unreadable.
pub(super) fn file_operand_hashes(
    arguments: &[String],
    cwd: &str,
    ctx: &Ctx,
) -> Option<Vec<Value>> {
    let mut bound: Vec<Value> = Vec::new();
    for argument in arguments {
        let value = argument_value(argument);
        if value.is_empty() || value.starts_with('-') {
            continue;
        }
        ctx.check().ok()?;
        let candidate = if fs_path::is_abs(value) {
            value.to_owned()
        } else {
            fs_path::join(cwd, value)
        };
        let Some(metadata) = probe(&candidate).ok()? else {
            // An absent operand is bound too, so creating the file re-prompts.
            bound.push(json!({"argument": argument, "sha256": "absent"}));
            continue;
        };
        if !metadata.is_file() {
            bound.push(json!({"argument": argument, "sha256": "non-file"}));
            continue;
        }
        let size = metadata.len();
        if size > MAX_BOUND_OPERAND_BYTES || bound.len() >= MAX_BOUND_OPERANDS {
            return None;
        }
        let digest = fs_path::sha256_hex(&std::fs::read(&candidate).ok()?);
        bound.push(json!({"argument": argument, "sha256": digest}));
    }
    Some(bound)
}
