//! `aibom_primary_content`: which inventory artifacts may upload the exact
//! body of their primary document, and the bounded read of that body.
//!
//! `admit` answers, per candidate, the root a primary document must stay
//! under (the nearest `skills` directory for a `SKILL.md`, the workspace for
//! a Markdown instruction) or null when the document may not be uploaded.
//! `read` checks the same path again, opens its resolved path without
//! following a final link, and returns the body only when it still hashes to the digest the
//! inventory advertised.

use std::io::Read;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::aibom_paths::{is_file, is_symlink, py_path, resolve, resolves_within_root};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};
use crate::skill_identity_platform::open_regular;

/// The content-upload route accepts at most 1 MiB per primary body.
const MAX_BODY_BYTES: u64 = 1024 * 1024;
const MAX_CANDIDATES: usize = 10_000;

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    match args.get("op").and_then(Value::as_str) {
        Some("admit") => admit(args),
        Some("read") => read(args),
        _ => Err(ERR_INVALID),
    }
}

fn admit(args: &Map<String, Value>) -> KindResult {
    let workspace = match args.get("workspace_dir") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => absolute_path(text),
        Some(_) => return Err(ERR_INVALID),
    };
    let candidates = args
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    if candidates.len() > MAX_CANDIDATES {
        return Err(ERR_INVALID);
    }
    let roots = candidates
        .iter()
        .map(|candidate| {
            let candidate = candidate.as_object().ok_or(ERR_INVALID)?;
            let instruction = match text(candidate, "artifact_type")? {
                "instruction" => true,
                "skill" => false,
                _ => return Err(ERR_INVALID),
            };
            let root = absolute_path(text(candidate, "path")?).and_then(|path| {
                let root = if instruction {
                    instruction_root(&path, workspace.as_deref())
                } else {
                    skill_root(&path)
                }?;
                safe_primary_path(&path, &root).then_some(root)
            });
            Ok(root.map_or(Value::Null, |root| {
                Value::String(root.to_string_lossy().into_owned())
            }))
        })
        .collect::<Result<Vec<Value>, &'static str>>()?;
    Ok(json!({ "allowed_roots": roots }))
}

fn read(args: &Map<String, Value>) -> KindResult {
    let path = absolute_path(text(args, "path")?);
    let root = absolute_path(text(args, "allowed_root")?);
    let expected = text(args, "content_hash")?;
    let body = match (path, root) {
        // The open takes the resolved path: a link above the allowed root
        // (a workspace reached through a Windows junction) was admitted, and
        // the Windows open refuses a link in any ancestor.
        (Some(path), Some(root)) if safe_primary_path(&path, &root) => resolve(&path)
            .ok()
            .and_then(|resolved| read_body(&resolved)),
        _ => None,
    };
    Ok(match body.filter(|body| content_hash(body) == expected) {
        Some(body) => json!({ "body_base64": STANDARD.encode(&body), "size": body.len() }),
        None => json!({ "body_base64": null }),
    })
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, &'static str> {
    object.get(key).and_then(Value::as_str).ok_or(ERR_INVALID)
}

/// A path the caller already expanded; anything relative is never admitted.
fn absolute_path(text: &str) -> Option<PathBuf> {
    let path = py_path(text);
    (!text.contains('\0') && path.is_absolute()).then_some(path)
}

/// `Path.suffix`: the last dot-suffix of a name that does not start with it.
fn python_suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(index) if index > 0 && index + 1 < name.len() => &name[index..],
        _ => "",
    }
}

fn instruction_root(path: &Path, workspace: Option<&Path>) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let suffix = python_suffix(name).to_lowercase();
    if suffix != ".md" && suffix != ".mdc" {
        return None;
    }
    workspace.map(Path::to_path_buf)
}

/// The nearest `skills` ancestor of a `SKILL.md` at least one directory below it.
fn skill_root(path: &Path) -> Option<PathBuf> {
    if path.file_name()?.to_str()? != "SKILL.md" {
        return None;
    }
    let skills = path.ancestors().skip(1).find(|parent| {
        parent
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.to_lowercase() == "skills")
    })?;
    let depth = path.strip_prefix(skills).ok()?.components().count();
    (depth >= 2).then(|| skills.to_path_buf())
}

/// A regular file that resolves under `root`, reached from `root` without
/// passing through a link at the root or any component below it.
fn safe_primary_path(path: &Path, root: &Path) -> bool {
    if !is_file(path) || !resolves_within_root(root, path, true) {
        return false;
    }
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    if is_symlink(root) {
        return false;
    }
    let mut current = root.to_path_buf();
    for part in relative.components() {
        current.push(part.as_os_str());
        if is_symlink(&current) {
            return false;
        }
    }
    true
}

fn read_body(path: &Path) -> Option<Vec<u8>> {
    let file = open_regular(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut body = Vec::new();
    file.take(MAX_BODY_BYTES + 1).read_to_end(&mut body).ok()?;
    u64::try_from(body.len())
        .is_ok_and(|length| length <= MAX_BODY_BYTES)
        .then_some(body)
}

fn content_hash(body: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(body)))
}

#[cfg(test)]
#[path = "aibom_primary_content_tests.rs"]
mod tests;
