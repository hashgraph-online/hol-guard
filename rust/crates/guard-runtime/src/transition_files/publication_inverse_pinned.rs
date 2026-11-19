//! What a Codex publication inverse pins, and the checks that it still holds,
//! ported from `_capture_predecessor_dependencies`,
//! `_capture_native_dependency` and `PreparedCodexPublicationInverse.compare_before`.
//!
//! An inverse pins the key and every artifact the authenticated predecessor
//! manifest runs, and once the review binds a verifier it also pins the
//! native runtime that verifies. These ops derive that set from the
//! predecessor, check it against what a plan captured, and extend a plan with
//! the verifier. A plan conveys no authority; nothing here writes.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::inspect::{decode, resolve_lenient};
use super::publication::Call;
use super::publication_generation::package_roots;
use super::publication_inverse_plan::check_op;
use super::publication_repair_files::{add, artifact, inverse};
use super::{compare, Ask, Fault, Step};
use crate::codex_hook_file_integrity_op::{admit, message};

type Object = Map<String, Value>;

const INVALID: Fault = Fault::Transition("native_transition_invalid");
const BINDING_INVALID: Fault = Fault::Transition("publication_inverse_native_binding_invalid");

pub(super) fn ask(call: &Call<'_>) -> Step<Ask> {
    Ok(Ask {
        budget: *call.budget,
        package_roots: package_roots(call.args)?
            .into_iter()
            .map(PathBuf::from)
            .collect(),
    })
}

fn values(files: &[Object]) -> Vec<Value> {
    files.iter().cloned().map(Value::Object).collect()
}

fn objects(value: Option<&Value>) -> Step<Vec<Object>> {
    value
        .and_then(Value::as_array)
        .ok_or(Fault::Transition("files_invalid"))?
        .iter()
        .map(|item| {
            item.as_object()
                .cloned()
                .ok_or(Fault::Transition("files_invalid"))
        })
        .collect()
}

/// The key and every artifact the authenticated predecessor `manifest` runs,
/// each checked to still hold what was pinned.
pub(super) fn predecessor_files(call: &Call<'_>, home: &Path, manifest: &str) -> Step<Vec<Object>> {
    let mut args = Map::new();
    args.insert("home".to_owned(), json!(home.to_string_lossy()));
    args.insert("manifest_text".to_owned(), json!(manifest));
    if let Some(roots) = call.args.get("package_roots") {
        args.insert("package_roots".to_owned(), roots.clone());
    }
    let answer = inverse(&mut Call {
        args: &args,
        budget: call.budget,
        events: Vec::new(),
    })?;
    let files = objects(answer.get("files"))?;
    compare(&values(&files), "before", false, &ask(call)?)?;
    Ok(files)
}

#[cfg(unix)]
fn mtime_ns(metadata: &fs::Metadata) -> i128 {
    use std::os::unix::fs::MetadataExt;
    i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec())
}

/// `os.stat` on Windows reports the write time in nanoseconds since 1970.
#[cfg(windows)]
fn mtime_ns(metadata: &fs::Metadata) -> i128 {
    use std::os::windows::fs::MetadataExt;
    const EPOCH_TICKS: i128 = 116_444_736_000_000_000;
    (i128::from(metadata.last_write_time()) - EPOCH_TICKS) * 100
}

fn sha256_text(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn integer(value: Option<&Value>) -> Option<i128> {
    let value = value?;
    if let Some(number) = value.as_i64() {
        return Some(i128::from(number));
    }
    value.as_u64().map(i128::from)
}

/// `_capture_native_dependency`: the native runtime pinned by its digest.
/// `runtime` is `{path, size, mtime_ns, sha256}` and `workspace` the
/// directory the verifier works in; one without the other is refused.
fn native_dependency(
    runtime: Option<&Value>,
    workspace: Option<&Value>,
    ask: &Ask,
) -> Step<Object> {
    let runtime = runtime.and_then(Value::as_object).ok_or(BINDING_INVALID)?;
    let workspace = workspace
        .and_then(Value::as_str)
        .map(Path::new)
        .ok_or(BINDING_INVALID)?;
    let path = runtime
        .get("path")
        .and_then(Value::as_str)
        .map(Path::new)
        .ok_or(BINDING_INVALID)?;
    let size = integer(runtime.get("size")).filter(|size| *size > 0);
    let mtime = integer(runtime.get("mtime_ns"));
    let digest = runtime.get("sha256").and_then(Value::as_str);
    let (Some(size), Some(mtime), Some(digest)) = (size, mtime, digest) else {
        return Err(BINDING_INVALID);
    };
    if !workspace.is_absolute()
        || resolve_lenient(workspace) != workspace
        || !workspace.is_dir()
        || !path.is_absolute()
        || resolve_lenient(path) != path
        || !sha256_text(digest)
    {
        return Err(BINDING_INVALID);
    }
    let (facts, file) = admit(path, "artifact", true, &ask.package_roots)
        .map_err(|reason| Fault::Integrity(reason.clone(), message(&reason)))?;
    let metadata = file.metadata()?;
    if mtime_ns(&metadata) != mtime || i128::from(facts.size) != size {
        return Err(Fault::Transition("native_runtime_generation_changed"));
    }
    let identity = json!({
        "path": path.to_string_lossy(),
        "size": runtime.get("size"),
        "sha256": digest,
        "mode": facts.mode & 0o777,
        "owner_uid": facts.uid,
        "role": "artifact",
    });
    artifact(identity.as_object().ok_or(INVALID)?, None)
}

/// The pins `manifest` implies, with the native runtime a bound plan names.
fn expected(
    call: &Call<'_>,
    home: &Path,
    manifest: &str,
    plan: &Map<String, Value>,
) -> Step<Vec<Object>> {
    let mut files = predecessor_files(call, home, manifest)?;
    let runtime = plan.get("native_runtime").filter(|value| !value.is_null());
    let workspace = plan
        .get("verification_workspace")
        .filter(|value| !value.is_null());
    if runtime.is_some() || workspace.is_some() {
        let pinned = native_dependency(runtime, workspace, &ask(call)?)?;
        add(&mut files, pinned, None)?;
    }
    Ok(files)
}

/// The tail of `compare_before` that needs no journal: the pins the
/// predecessor implies are exactly `dependencies`, and each still holds.
fn confirm(call: &Call<'_>, home: &Path, manifest: &[u8]) -> Step<Value> {
    let manifest = std::str::from_utf8(manifest).map_err(|_| INVALID)?;
    let files = expected(call, home, manifest, call.args)?;
    let captured = objects(call.args.get("dependencies"))?;
    if files != captured {
        return Err(Fault::Transition(
            "publication_inverse_dependencies_invalid",
        ));
    }
    compare(&values(&files), "before", false, &ask(call)?)?;
    call.budget.hook()?;
    Ok(Value::Null)
}

/// `publication_inverse_pinned`: the predecessor `manifest_text` still pins
/// exactly `dependencies`, with the `native_runtime` and
/// `verification_workspace` a bound plan names.
pub(super) fn pinned(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let manifest = call.text("manifest_text")?.to_owned();
    confirm(call, &home, manifest.as_bytes())
}

/// `publication_inverse_verify`: `compare_before` after the owner checks. The
/// journal, the record and every captured target still hold what the plan
/// captured, and the predecessor still pins exactly its dependencies.
pub(super) fn verify(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    call.budget.hook()?;
    let captured = check_op(call)?;
    let predecessor = decode(Some(&captured))?.ok_or(Fault::Transition(
        "publication_inverse_predecessor_authority_missing",
    ))?;
    confirm(call, &home, &predecessor)
}

/// `publication_inverse_bind`: the `dependencies` of a plan extended with the
/// native runtime and workspace the review binds. Answer: `{"files": [...]}`.
pub(super) fn bind(call: &mut Call<'_>) -> Step<Value> {
    let mut files = objects(call.args.get("dependencies"))?;
    let pinned = native_dependency(
        call.args.get("native_runtime"),
        call.args.get("verification_workspace"),
        &ask(call)?,
    )?;
    add(&mut files, pinned, None)?;
    Ok(json!({ "files": files }))
}

#[cfg(test)]
#[path = "tests_publication_inverse_pinned.rs"]
mod tests;
