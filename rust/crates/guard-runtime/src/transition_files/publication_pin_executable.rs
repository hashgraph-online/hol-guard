//! Pinning one executable the way a runtime transition binds it, ported from
//! `runtime_transition_prepare._pin_executable`.
//!
//! The file must pass the artifact checks, and its identity from `lstat`, from
//! the descriptor opened without following a link, and from `lstat` again
//! after the whole file was hashed must be one generation. What comes back is
//! the artifact dependency record the plan carries: the path, its mode and
//! owner, its size and its SHA-256.

use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::publication::Call;
use super::publication_authorize::{ahead, number};
use super::publication_pin_stamp as stamp;
use super::python_equal::python_equal;
use super::{Fault, Step};
use crate::codex_hook_file_integrity_op::{message, validate};

const CHUNK: usize = 64 * 1024;
const GENERATION: Fault = Fault::Transition("generation_changed");
const EXPIRED: Fault = Fault::Transition("deadline_exceeded");
const ARTIFACT_CHANGED: Fault = Fault::Transition("artifact_generation_changed");
const RUNTIME_CHANGED: Fault = Fault::Transition("native_runtime_generation_changed");
/// The longest a caller's budget may be, as `Budget` caps its own.
const MAX_SECONDS: f64 = 600.0;

/// The caller's deadline as a moment on this clock: `deadline_exceeded` unless
/// `deadline` is a finite number still ahead of `now`, the caller's monotonic
/// seconds. What remains is all the runtime can share.
pub(super) fn deadline_of(call: &Call<'_>) -> Step<Instant> {
    let now = number(call, "now");
    let deadline = ahead(number(call, "deadline"), now)?;
    let remaining = (deadline - now.unwrap_or(deadline)).clamp(0.0, MAX_SECONDS);
    Ok(Instant::now() + Duration::from_secs_f64(remaining))
}

pub(super) fn alive(deadline: Instant) -> Step<()> {
    if Instant::now() >= deadline {
        return Err(EXPIRED);
    }
    Ok(())
}

fn roots(call: &Call<'_>) -> Vec<PathBuf> {
    call.args
        .get("package_roots")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

/// `validate_regular_file(path, role="artifact", executable_required=True)`.
fn admit(call: &Call<'_>, path: &Path) -> Step<()> {
    call.budget.hook()?;
    validate(path, "artifact", true, &roots(call)).map_err(|reason| {
        let wording = message(&reason);
        Fault::Integrity(reason, wording)
    })?;
    call.budget.hook()
}

/// What a pin must still match: the identity a caller inspected earlier.
#[derive(Default)]
pub(super) struct Expect<'a> {
    pub(super) identity: Option<&'a Map<String, Value>>,
    pub(super) sha256: Option<&'a str>,
}

/// `_pin_executable`: the artifact dependency record for `path`, or the
/// reason it is not one generation of one executable.
pub(super) fn pin(
    call: &Call<'_>,
    path: &Path,
    deadline: Instant,
    expect: &Expect<'_>,
) -> Step<Value> {
    alive(deadline)?;
    // The identity is read before admission, so the mode and owner admission
    // checked are those of the generation the descriptor must still match.
    let before = stamp::of_path(path);
    admit(call, path)?;
    let before = before.map_err(|_| {
        Fault::Integrity(
            "codex_hook_artifact_missing".to_owned(),
            message("codex_hook_artifact_missing"),
        )
    })?;
    let mut file = stamp::open(path)?;
    let opened = stamp::of_file(&file)?;
    if before != opened {
        return Err(GENERATION);
    }
    let facts = stamp::facts(&file)?;
    let mut digest = Sha256::new();
    let mut count: u64 = 0;
    let mut buffer = vec![0_u8; CHUNK];
    loop {
        alive(deadline)?;
        let read = match file.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        alive(deadline)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > facts.size {
            return Err(GENERATION);
        }
        digest.update(&buffer[..read]);
    }
    if count != facts.size || stamp::of_file(&file)? != opened || stamp::of_path(path)? != opened {
        return Err(GENERATION);
    }
    let sha256 = hex(&digest.finalize());
    if expect.sha256.is_some_and(|wanted| wanted != sha256) {
        return Err(ARTIFACT_CHANGED);
    }
    if let Some(identity) = expect.identity {
        let same = |key: &str, actual: Option<Value>| match (identity.get(key), actual) {
            (Some(wanted), Some(actual)) => python_equal(wanted, &actual),
            _ => false,
        };
        if !same("sha256", Some(json!(sha256)))
            || !same("size", Some(json!(count)))
            || !same(
                "mtime_ns",
                i64::try_from(facts.mtime_ns).ok().map(Value::from),
            )
        {
            return Err(RUNTIME_CHANGED);
        }
    }
    alive(deadline)?;
    Ok(json!({
        "path": path.to_string_lossy(),
        "mode": facts.mode & 0o777,
        "owner_uid": facts.uid,
        "size": count,
        "sha256": sha256,
        "role": "artifact",
    }))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// `publication_pin_executable`: pin `path` within `deadline` (with `now`, the
/// caller's monotonic seconds). `expected` is the runtime identity the file
/// must still be (`sha256`, `size`, `mtime_ns`) and `expected_sha256` the
/// digest a reviewed artifact bound; either may be null.
pub(super) fn pin_op(call: &mut Call<'_>) -> Step<Value> {
    let deadline = deadline_of(call)?;
    let path = PathBuf::from(call.text("path")?);
    let identity = match call.args.get("expected") {
        None | Some(Value::Null) => None,
        Some(Value::Object(identity)) => Some(identity),
        Some(_) => return Err(Fault::Transition("files_invalid")),
    };
    let sha256 = match call.args.get("expected_sha256") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.as_str()),
        Some(_) => return Err(Fault::Transition("files_invalid")),
    };
    pin(call, &path, deadline, &Expect { identity, sha256 })
}
