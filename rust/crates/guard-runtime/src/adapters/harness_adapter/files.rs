//! The file reads an install plan rests on and the plan's wire form.
//!
//! `snapshot` reads a file as `codex_hook_recovery._snapshot` does, and
//! `output_path` normalises an output path as `safe_output._normalized_output_path`
//! does. A plan entry carries the bytes before and after and the modes, which
//! Python wraps in a `TransitionFile` and publishes through the runtime
//! transition journal.

use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};

use super::{path_text, Ctx, Failure, Step};
use crate::aibom_paths::resolves_within_root;
use crate::hook_removal_prune::write_indented;
use crate::pyjson::PyVal;

const MAX_SNAPSHOT: u64 = 4 * 1024 * 1024;

#[cfg(unix)]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

/// One regular file, owned by the caller, with a single link.
#[cfg(unix)]
fn trusted_target(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.is_file()
        && meta.nlink() == 1
        && meta.len() <= MAX_SNAPSHOT
        && meta.uid() == nix::unistd::geteuid().as_raw()
}

#[cfg(windows)]
fn trusted_target(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_POINT: u32 = 0x400;
    meta.is_file() && meta.len() <= MAX_SNAPSHOT && meta.file_attributes() & REPARSE_POINT == 0
}

#[cfg(unix)]
fn same_file(opened: &fs::Metadata, current: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    (opened.dev(), opened.ino()) == (current.dev(), current.ino())
}

#[cfg(not(unix))]
fn same_file(opened: &fs::Metadata, current: &fs::Metadata) -> bool {
    opened.len() == current.len() && !current.file_type().is_symlink()
}

/// `_snapshot(path)`: the bytes, `None` when absent, or the integrity reason.
pub(crate) fn snapshot(ctx: &Ctx, path: &Path) -> Step<Option<Vec<u8>>> {
    let path = ctx.absolute(path);
    let invalid = || Failure::Integrity("target_invalid");
    let mut file = match open_no_follow(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return if path.is_symlink() {
                Err(invalid())
            } else {
                Ok(None)
            };
        }
        Err(_) => return Err(invalid()),
    };
    let opened = file.metadata().map_err(|_| invalid())?;
    if !trusted_target(&opened) {
        return Err(invalid());
    }
    let mut value = Vec::new();
    (&mut file)
        .take(MAX_SNAPSHOT + 1)
        .read_to_end(&mut value)
        .map_err(|_| invalid())?;
    let current = fs::symlink_metadata(&path).map_err(|_| Failure::Integrity("target_changed"))?;
    if value.len() as u64 > MAX_SNAPSHOT || !same_file(&opened, &current) {
        return Err(Failure::Integrity("target_changed"));
    }
    Ok(Some(value))
}

/// `path.stat().st_mode & 0o777`, following links.
#[cfg(unix)]
pub(crate) fn mode(ctx: &Ctx, path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(ctx.absolute(path))
        .ok()
        .map(|meta| meta.permissions().mode() & 0o777)
}

/// CPython's Windows `st_mode`: read-only or not, executable by extension.
#[cfg(not(unix))]
pub(crate) fn mode(ctx: &Ctx, path: &Path) -> Option<u32> {
    let meta = fs::metadata(ctx.absolute(path)).ok()?;
    let mut mode = if meta.permissions().readonly() {
        0o444
    } else {
        0o666
    };
    let executable = path
        .extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|ext| matches!(ext.as_str(), "exe" | "bat" | "cmd" | "com"));
    if meta.is_dir() || executable {
        mode |= 0o111;
    }
    Some(mode)
}

/// `_ensure_path_within_root(root, path, label=label)`.
pub(crate) fn within_root(ctx: &Ctx, root: &Path, path: &Path, label: &str) -> Step<()> {
    if resolves_within_root(&ctx.absolute(root), &ctx.absolute(path), false) {
        Ok(())
    } else {
        Err(Failure::Refusal(format!(
            "{label} settings path escapes the managed root"
        )))
    }
}

#[cfg(unix)]
fn trusted_system_link(candidate: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let parent = candidate.parent().unwrap_or(candidate);
    match (
        fs::symlink_metadata(candidate),
        fs::symlink_metadata(parent),
    ) {
        (Ok(link), Ok(parent)) => {
            link.uid() == 0 && parent.uid() == 0 && parent.mode() & 0o022 == 0
        }
        _ => false,
    }
}

#[cfg(not(unix))]
fn trusted_system_link(_candidate: &Path) -> bool {
    false
}

/// `_normalized_output_path(path)`: the first missing directory ends the
/// walk, and only a root-owned link in a root-owned directory is followed.
pub(crate) fn output_path(ctx: &Ctx, path: &Path) -> Step<PathBuf> {
    let absolute = ctx.absolute(path);
    let name = absolute.file_name().map(PathBuf::from).unwrap_or_default();
    let parent = absolute.parent().unwrap_or(&absolute);
    let mut current = PathBuf::new();
    let mut parts = Vec::new();
    for component in parent.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            other => parts.push(other.as_os_str().to_owned()),
        }
    }
    for (index, part) in parts.iter().enumerate() {
        let candidate = current.join(part);
        let meta = match fs::symlink_metadata(&candidate) {
            Ok(meta) => meta,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let mut rest = candidate;
                rest.extend(&parts[index + 1..]);
                return Ok(rest.join(name));
            }
            Err(error) => return Err(Failure::Os(error.to_string())),
        };
        current = if meta.file_type().is_symlink() {
            if !trusted_system_link(&candidate) {
                return Err(Failure::Os(format!(
                    "refusing symlinked output directory: {}",
                    path_text(&candidate)
                )));
            }
            fs::canonicalize(&candidate).map_err(|error| Failure::Os(error.to_string()))?
        } else {
            candidate
        };
    }
    Ok(current.join(name))
}

fn encoded(bytes: Option<&[u8]>) -> Value {
    bytes.map_or(Value::Null, |bytes| json!(STANDARD.encode(bytes)))
}

/// One `TransitionFile` of a plan.
pub(crate) struct Change {
    pub(crate) path: PathBuf,
    pub(crate) before: Option<Vec<u8>>,
    pub(crate) after: Option<Vec<u8>>,
    pub(crate) before_mode: u32,
    pub(crate) after_mode: u32,
    pub(crate) no_follow: bool,
}

impl Change {
    /// A change at `path.resolve(strict=False)`.
    pub(crate) fn at(
        ctx: &Ctx,
        path: &Path,
        before: Option<Vec<u8>>,
        after: Option<Vec<u8>>,
        mode: u32,
    ) -> Self {
        Self {
            path: ctx.resolved(path),
            before,
            after,
            before_mode: mode,
            after_mode: mode,
            no_follow: false,
        }
    }

    pub(crate) fn wire(&self) -> Value {
        json!({
            "path": path_text(&self.path),
            "before": encoded(self.before.as_deref()),
            "after": encoded(self.after.as_deref()),
            "before_mode": self.before_mode,
            "after_mode": self.after_mode,
            "no_follow": self.no_follow,
        })
    }
}

/// A Python dict built in insertion order; a repeated key keeps its place.
#[derive(Default)]
pub(crate) struct Doc(pub(crate) Vec<(String, PyVal)>);

impl Doc {
    pub(crate) fn set(&mut self, key: &str, value: PyVal) -> &mut Self {
        match self.0.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
        self
    }

    /// `{**other}` spread at this point.
    pub(crate) fn spread(&mut self, other: &[(String, PyVal)]) -> &mut Self {
        for (key, value) in other {
            self.set(key, value.clone());
        }
        self
    }

    pub(crate) fn value(self) -> PyVal {
        PyVal::Dict(self.0)
    }
}

pub(crate) fn text(value: impl Into<String>) -> PyVal {
    PyVal::Str(value.into())
}

pub(crate) fn path_value(path: &Path) -> PyVal {
    text(path_text(path))
}

/// `json.dumps(value, indent=2)`.
pub(crate) fn render(value: &PyVal) -> Step<String> {
    let mut out = Vec::new();
    write_indented(value, 0, &mut out).ok_or(Failure::Invalid)?;
    String::from_utf8(out).map_err(|_| Failure::Invalid)
}

/// The shim manifest Python prepared or removed, as a JSON object string.
pub(crate) fn shim_manifest(fields: &serde_json::Map<String, Value>) -> Step<Vec<(String, PyVal)>> {
    let raw = fields
        .get("shim")
        .and_then(Value::as_str)
        .ok_or(Failure::Invalid)?;
    match crate::pyjson::parse(raw) {
        Ok(PyVal::Dict(entries)) => Ok(entries),
        _ => Err(Failure::Invalid),
    }
}

/// The string notes of a shim manifest.
pub(crate) fn shim_notes(shim: &[(String, PyVal)]) -> Vec<PyVal> {
    shim.iter()
        .find(|(key, _)| key == "notes")
        .and_then(|(_, notes)| notes.as_list())
        .map(|notes| {
            notes
                .iter()
                .filter(|note| matches!(note, PyVal::Str(_)))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

/// `{"harness", "active", "config_path", **shim, "notes": [*notes, *shim_notes]}`.
pub(crate) fn adapter_result(
    harness: &str,
    active: bool,
    config_path: &Path,
    shim: &[(String, PyVal)],
    notes: Vec<PyVal>,
) -> Doc {
    let mut doc = Doc::default();
    doc.set("harness", text(harness))
        .set("active", PyVal::Bool(active))
        .set("config_path", path_value(config_path))
        .spread(shim);
    let mut all = notes;
    all.extend(shim_notes(shim));
    doc.set("notes", PyVal::List(all));
    doc
}

/// The answer carrying a finished manifest.
pub(crate) fn manifest_answer(doc: Doc) -> Step<Value> {
    Ok(json!({ "manifest": render(&doc.value())? }))
}

/// `finish_uninstall`: the inactive manifest with the plan's notes before the
/// removed shim's.
pub(crate) fn finished(
    harness: &str,
    config_path: &Path,
    fields: &serde_json::Map<String, Value>,
) -> Step<Value> {
    let shim = shim_manifest(fields)?;
    let notes = fields
        .get("finish")
        .and_then(|finish| finish.get("notes"))
        .and_then(Value::as_array)
        .ok_or(Failure::Invalid)?
        .iter()
        .map(|note| note.as_str().map(text).ok_or(Failure::Invalid))
        .collect::<Step<Vec<_>>>()?;
    manifest_answer(adapter_result(harness, false, config_path, &shim, notes))
}
