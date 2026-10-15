//! Package-manager executable identity (`executable_material`).

use std::collections::{BTreeMap, BTreeSet};

use crate::launch_identity_common::sha256_hex;
use serde_json::Value;

use crate::codex_output_py::PyPath;
use crate::hook_adapter_value::OValue;

use super::fs::{ContextFiles, Fs, ResolveError, MAX_EXECUTABLE_BYTES};
use super::ports::Ports;
use super::{object, path_name, text, BuildError, Built};

const LAUNCH_UNAVAILABLE: &str = "package_manager_launch_identity_unavailable";
const EXECUTABLE_UNAVAILABLE: &str = "package_manager_executable_unavailable";

pub(super) struct ExecutableInput<'a> {
    pub(super) workspace: &'a str,
    pub(super) repository_root: Option<&'a str>,
    pub(super) manager: &'a str,
    pub(super) executable: Option<&'a str>,
    pub(super) arguments: &'a [String],
    pub(super) environment: &'a BTreeMap<String, String>,
    pub(super) fallback_path: Option<&'a str>,
}

/// `os.access(path, X_OK)` plus `exists` and not-a-directory (`shutil._access_check`).
fn executable_file(fs: &Fs, path: &str) -> Built<bool> {
    // `os.path.exists` and `os.path.isdir` swallow every OSError, so an
    // untraversable PATH entry is skipped instead of failing the build.
    if !matches!(fs.exists(path), Ok(true)) || matches!(fs.is_dir(path), Ok(true) | Err(_)) {
        return Ok(false);
    }
    Ok(nix::unistd::access(&fs.fs_path(path), nix::unistd::AccessFlags::X_OK).is_ok())
}

/// `shutil.which(name, path=...)` for a bare command name.
fn which(fs: &Fs, name: &str, search_path: &str) -> Built<Option<String>> {
    if search_path.is_empty() {
        return Ok(None);
    }
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for directory in search_path.split(':') {
        if !seen.insert(directory) {
            continue;
        }
        let candidate = if directory.is_empty() {
            name.to_owned()
        } else if directory.ends_with('/') {
            format!("{directory}{name}")
        } else {
            format!("{directory}/{name}")
        };
        if executable_file(fs, &candidate)? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

fn resolve_strict(fs: &Fs, path: &str) -> Built<Option<String>> {
    match fs.resolve(path, true) {
        Ok(resolved) => Ok(Some(resolved)),
        Err(ResolveError::Os) => Ok(None),
        Err(other) => Err(other.into_fatal(path)),
    }
}

fn locate(fs: &Fs, input: &ExecutableInput<'_>, requested: &str) -> Built<Option<String>> {
    if requested.contains('/') || requested.contains('\\') {
        let expanded = fs.expanduser(requested)?;
        let candidate = if expanded.starts_with('/') {
            expanded
        } else {
            PyPath::new(input.workspace).join(&expanded).to_string()
        };
        return resolve_strict(fs, &candidate);
    }
    let search = input
        .environment
        .get("PATH")
        .map(String::as_str)
        .or(input.fallback_path);
    let Some(search) = search else {
        return Ok(None);
    };
    match which(fs, requested, search)? {
        Some(found) => fs
            .resolve(&found, false)
            .map(Some)
            .map_err(|error| error.into_fatal(&found)),
        None => Ok(None),
    }
}

/// `_canonical_executable_location`.
fn canonical_location(candidate: &str, workspace: &str, repository_root: Option<&str>) -> String {
    let path = PyPath::new(candidate);
    for (label, root) in [
        ("workspace", Some(workspace)),
        ("repository", repository_root),
    ] {
        let Some(root) = root else { continue };
        if let Some(parts) = path.relative_to(&PyPath::new(root)) {
            let relative = if parts.is_empty() {
                ".".to_owned()
            } else {
                parts.join("/")
            };
            return format!("{label}:{relative}");
        }
    }
    format!("external:{candidate}")
}

/// `_portable_launch_identity`.
fn portable_identity(
    value: &Value,
    workspace: &str,
    repository_root: Option<&str>,
) -> Built<OValue> {
    Ok(match value {
        Value::Object(map) => {
            let mut normalized = crate::hook_adapter_value::OMap::new();
            for (key, item) in map {
                let tracked = matches!(key.as_str(), "path" | "launch_cwd" | "command");
                if let (true, Value::String(raw)) = (tracked, item) {
                    let replacement = if PyPath::new(raw).is_absolute() {
                        canonical_location(raw, workspace, repository_root)
                    } else {
                        raw.clone()
                    };
                    normalized.insert(key, OValue::Str(replacement));
                    continue;
                }
                normalized.insert(key, portable_identity(item, workspace, repository_root)?);
            }
            OValue::Map(normalized)
        }
        Value::Array(items) => OValue::List(
            items
                .iter()
                .map(|item| portable_identity(item, workspace, repository_root))
                .collect::<Built<Vec<_>>>()?,
        ),
        other => OValue::from_wire(other).map_err(|reason| {
            BuildError::Fatal(format!("unrepresentable launch identity value: {reason}"))
        })?,
    })
}

fn unavailable(manager: &str, requested: &str, status: &str) -> OValue {
    object(vec![
        ("manager", text(manager)),
        ("requested", text(&path_name(requested))),
        ("status", text(status)),
    ])
}

pub(super) fn executable_material(
    fs: &Fs,
    files: &mut ContextFiles,
    ports: &mut dyn Ports,
    input: &ExecutableInput<'_>,
) -> Built<(OValue, Option<&'static str>)> {
    let manager = input.manager;
    let requested = match input.executable {
        Some(value) if !value.is_empty() => value,
        _ => manager,
    };
    if requested.is_empty()
        || requested == "unknown"
        || [";", "&&", "||", "|"]
            .iter()
            .any(|token| requested.contains(token))
    {
        return Ok((
            object(vec![
                ("manager", text(manager)),
                ("status", text("unavailable")),
            ]),
            Some(EXECUTABLE_UNAVAILABLE),
        ));
    }
    let Some(candidate) = locate(fs, input, requested)? else {
        return Ok((
            unavailable(manager, requested, "unavailable"),
            Some(EXECUTABLE_UNAVAILABLE),
        ));
    };
    let payload = match files.read(fs, &candidate, MAX_EXECUTABLE_BYTES, true) {
        Ok(payload) => payload,
        Err(BuildError::Unavailable(reason)) => {
            return Ok((unavailable(manager, requested, reason), Some(reason)));
        }
        Err(fatal) => return Err(fatal),
    };
    let location = canonical_location(&candidate, input.workspace, input.repository_root);
    let search_path = input.environment.get("PATH").map(String::as_str);
    let identity = ports.launch_identity(
        requested,
        input.arguments,
        search_path,
        input.workspace,
        input.environment,
    );
    let content_digest = sha256_hex(&payload);
    let verified = identity.get("executable").is_some_and(|executable| {
        executable.is_object()
            && executable.get("status").and_then(Value::as_str) == Some("verified")
            && executable.get("sha256").and_then(Value::as_str) == Some(content_digest.as_str())
    });
    if !verified {
        return Ok((
            unavailable(manager, requested, LAUNCH_UNAVAILABLE),
            Some(LAUNCH_UNAVAILABLE),
        ));
    }
    let mut material = vec![
        ("content_digest", text(&content_digest)),
        (
            "launch_identity",
            portable_identity(&identity, input.workspace, input.repository_root)?,
        ),
        ("location", text(&location)),
        ("manager", text(manager)),
        ("requested", text(&path_name(requested))),
    ];
    if !(requested.contains('/') || requested.contains('\\')) {
        let digest = ports.opaque_digest(search_path.unwrap_or(""));
        material.push(("search_path_digest", text(&digest)));
    }
    if !ports.launch_identity_reusable(&identity) {
        material.push(("status", text(LAUNCH_UNAVAILABLE)));
        return Ok((object(material), Some(LAUNCH_UNAVAILABLE)));
    }
    Ok((object(material), None))
}
